from __future__ import annotations

import asyncio
import json
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from app.agents.anomaly_agent import AnomalyAgent
from app.agents.attribution_agent import AttributionAgent
from app.agents.cve_agent import CveAgent
from app.agents.graph_agent import GraphAgent
from app.agents.orchestrator_agent import OrchestratorAgent
from app.audit.audit_log import AuditLog
from app.config import get_settings
from app.db import db_health, init_db, sync_alerts, sync_events, upsert_alert, upsert_event
from app.eval.harness import build_alerts, severity_for
from app.ingest.exam_app_adapter import normalize_frontend_event
from app.ingest.synth_generator import generate_events
from app.models.schemas import Alert, RawEvent, TelemetryEvent
from app.paths import ALERTS_PATH, EVAL_REPORT_PATH, EVENTS_PATH, ensure_dirs
from app.storage import append_jsonl, read_json, read_jsonl, utc_now, write_json, write_jsonl
from app.security import OperatorAuth, check_ingest_rate_limit


app = FastAPI(title="Aegis-CNI Behavioural Resilience API", version="0.1.0")
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

audit = AuditLog()
anomaly_agent = AnomalyAgent()
attribution_agent = AttributionAgent()
orchestrator_agent = OrchestratorAgent(audit=audit, blast_threshold=settings.high_blast_radius_threshold)
cve_agent = CveAgent()
graph_agent = GraphAgent()
EVENTS: list[TelemetryEvent] = []
ALERTS: list[Alert] = []


def _load_events() -> list[TelemetryEvent]:
    rows = read_jsonl(EVENTS_PATH)
    if not rows:
        events = generate_events()
        write_jsonl(EVENTS_PATH, [e.model_dump() for e in events])
        return events
    return [TelemetryEvent.model_validate(row) for row in rows]


def _load_alerts() -> list[Alert]:
    rows = read_json(ALERTS_PATH, [])
    return [Alert.model_validate(row) for row in rows]


@app.on_event("startup")
def startup() -> None:
    ensure_dirs()
    init_db()
    global EVENTS, ALERTS
    EVENTS = _load_events()
    anomaly_agent.fit(EVENTS)
    ALERTS = _load_alerts()
    if not ALERTS:
        ALERTS = build_alerts(EVENTS, anomaly_agent, attribution_agent)
        write_json(ALERTS_PATH, [a.model_dump() for a in ALERTS])
    sync_events([event.model_dump() for event in EVENTS])
    sync_alerts([alert.model_dump() for alert in ALERTS])


@app.get("/health")
def health() -> dict:
    return {"ok": True, "events": len(EVENTS), "alerts": len(ALERTS)}


@app.get("/ready")
def ready() -> dict:
    return {
        "ok": True,
        "database": db_health(),
        "anomaly_model_fit": anomaly_agent._fit,
        "mitre_techniques": len(attribution_agent.retriever.techniques),
    }


@app.post("/ingest/events", status_code=202)
def ingest_event(raw: RawEvent, request: Request, _: None = Depends(check_ingest_rate_limit)) -> dict:
    event = normalize_frontend_event(raw)
    EVENTS.append(event)
    append_jsonl(EVENTS_PATH, event.model_dump())
    upsert_event(event.model_dump())
    score = anomaly_agent.score(event)
    alert_id = None
    if score >= anomaly_agent.threshold:
        alert_id = f"ALT-{len(ALERTS) + 1:05d}"
        attribution = attribution_agent.attribute(alert_id, event, score)
        ALERTS.insert(
            0,
            Alert(
                alert_id=alert_id,
                event=event,
                anomaly_score=round(score, 3),
                severity=severity_for(score),
                title=f"{attribution.techniques[0].id} {attribution.techniques[0].name} on {event.segment}",
                attribution=attribution,
                created_at=utc_now(),
            ),
        )
        write_json(ALERTS_PATH, [a.model_dump() for a in ALERTS])
        upsert_alert(ALERTS[0].model_dump())
        audit.append(
            actor="anomaly_agent",
            action="raise_alert",
            justification=f"Frontend event exceeded behavioural anomaly threshold ({score:.2f}).",
            blast_radius=1,
            payload={"event_id": event.event_id, "alert_id": alert_id},
        )
    return {"accepted": True, "score": round(score, 3), "alert_id": alert_id}


@app.get("/alerts")
def get_alerts(
    severity: str | None = None,
    technique: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    rows = ALERTS
    if severity:
        rows = [alert for alert in rows if alert.severity == severity]
    if technique:
        rows = [alert for alert in rows if any(t.id == technique for t in alert.attribution.techniques)]
    return {"items": [alert.model_dump() for alert in rows[:limit]], "total": len(rows)}


@app.get("/alerts/stream")
async def alert_stream() -> EventSourceResponse:
    async def generator():
        idx = 0
        while True:
            if ALERTS:
                alert = ALERTS[idx % len(ALERTS)]
                yield {"event": "alert", "data": json.dumps(alert.model_dump(), default=str)}
                idx += 1
            await asyncio.sleep(2)

    return EventSourceResponse(generator())


@app.get("/attribution/{alert_id}")
def get_attribution(alert_id: str) -> dict:
    alert = next((row for row in ALERTS if row.alert_id == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.attribution.model_dump()


@app.post("/playbooks/{alert_id}/run", dependencies=[OperatorAuth])
def run_playbook(alert_id: str) -> dict:
    alert = next((row for row in ALERTS if row.alert_id == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    run = orchestrator_agent.run(alert)
    alert.status = "queued" if run.status == "queued_for_approval" else "contained"
    return run.model_dump()


@app.post("/playbooks/{run_id}/approve", dependencies=[OperatorAuth])
def approve_playbook(run_id: str) -> dict:
    run = orchestrator_agent.approve(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run.model_dump()


@app.get("/cve-queue")
def cve_queue() -> dict:
    observed = [alert.attribution.techniques[0].id for alert in ALERTS]
    return {"items": cve_agent.rank(observed)}


@app.get("/twin/graph")
def twin_graph() -> dict:
    return graph_agent.export()


@app.post("/twin/simulate", dependencies=[OperatorAuth])
def twin_simulate() -> dict:
    audit.append(
        actor="graph_agent",
        action="simulate_attack_path",
        justification="Operator requested labelled digital-twin attack path simulation.",
        blast_radius=0,
        payload={"model_only": True},
    )
    return graph_agent.simulate()


@app.get("/audit")
def get_audit(limit: int = Query(100, ge=1, le=500)) -> dict:
    return {"items": [entry.model_dump() for entry in audit.entries(limit=limit)]}


@app.get("/audit/verify")
def verify_audit() -> dict:
    return audit.verify()


@app.get("/eval/report")
def eval_report() -> JSONResponse:
    report = read_json(EVAL_REPORT_PATH, {})
    if not report:
        return JSONResponse(status_code=404, content={"detail": "Run python seed.py to generate eval report."})
    return JSONResponse(content=report)
