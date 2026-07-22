from __future__ import annotations

import asyncio
import base64
import json
import random
import time
from dataclasses import asdict
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sse_starlette.sse import EventSourceResponse

from app.agents.anomaly_agent import AnomalyAgent
from app.agents.attribution_agent import AttributionAgent
from app.agents.cve_agent import CveAgent
from app.agents.graph_agent import GraphAgent
from app.agents.orchestrator_agent import OrchestratorAgent
from app.agents.predictive_risk_agent import PredictiveRiskAgent, RiskPrediction
from app.audit.audit_log import AuditLog
from app.config import get_settings
from app.db import db_health, init_db, sync_alerts, sync_events, upsert_alert, upsert_event
from app.eval.harness import build_alerts, severity_for
from app.ingest.exam_app_adapter import normalize_frontend_event
from app.ingest.attack_simulation import build_attack_event, find_technique
from app.ingest.nvd_client import refresh_nvd_cache
from app.ingest.synth_generator import generate_events
from app.integrations.connectors import connector_catalog
from app.models.schemas import Alert, CopilotQuestion, RawEvent, TelemetryEvent
from app.paths import ALERTS_PATH, EVAL_REPORT_PATH, EVENTS_PATH, ensure_dirs
from app.storage import append_jsonl, read_json, read_jsonl, utc_now, write_json, write_jsonl
from app.security import GLOBAL_BLOCKLIST, GLOBAL_RATE_TRACKER, OperatorAuth, RateSignal, check_ingest_rate_limit
from app.security.signatures import SignatureMatch, scan_request
from app.agents.zero_day_strategy import zero_day_prevention_strategy


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
risk_agent = PredictiveRiskAgent(threshold=settings.predictive_risk_threshold)
orchestrator_agent = OrchestratorAgent(audit=audit, blast_threshold=settings.high_blast_radius_threshold)
cve_agent = CveAgent()
graph_agent = GraphAgent()
EVENTS: list[TelemetryEvent] = []
ALERTS: list[Alert] = []
DEMO_TASK: asyncio.Task | None = None
GENAI_WARMUP_TASK: asyncio.Task | None = None
DEMO_PAUSED = False
DEMO_NORMAL_POOL: list[TelemetryEvent] = []
DEMO_ATTACK_TECHNIQUES = ["T1110", "T1078", "T1021", "T1499"]
DEMO_STATS = {"benign_events": 0, "attack_events": 0, "last_event": None, "last_alert_id": None}
MIDDLEWARE_SKIP_PREFIXES = ("/alerts/stream",)
LOCAL_SOC_READ_PREFIXES = (
    "/alerts",
    "/audit",
    "/blocks",
    "/ready",
    "/eval/report",
    "/cve-queue",
    "/twin/graph",
    "/demo/status",
    "/coverage",
    "/prevention",
    "/integrations",
    "/incidents",
)
DENY_MESSAGE = "Aegis-CNI perimeter blocklist denied this request."
ACTIVE_LIVE_TECHNIQUES = {
    "T1059": "command injection-shaped request detection",
    "T1083": "path traversal-shaped request detection",
    "T1110": "failed-login/brute-force pressure",
    "T1189": "XSS-shaped request detection",
    "T1190": "SQLi/public-app exploit-shaped request detection",
    "T1499": "oversized/malformed request pressure",
    "T1595": "request burst and endpoint enumeration",
}


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


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _allow_local_blocked_soc_read(request: Request, ip: str, path: str) -> bool:
    if request.method not in {"GET", "OPTIONS"}:
        return False
    if request.headers.get("x-forwarded-for"):
        return False
    if ip not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        return False
    return any(path.startswith(prefix) for prefix in LOCAL_SOC_READ_PREFIXES)


def _set_replay_body(request: Request, body: bytes) -> None:
    async def receive() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    request._receive = receive  # type: ignore[attr-defined]


def _maybe_parse_body(body: bytes, content_type: str) -> str:
    if not body:
        return ""
    text = body[:8192].decode("utf-8", errors="replace")
    if "application/json" in content_type:
        try:
            return json.dumps(json.loads(text), sort_keys=True)
        except Exception:
            return text
    return text


def _extract_auth_context(request: Request, body_text: str) -> tuple[str, str]:
    user_id = request.headers.get("x-user-id") or "anonymous"
    role = request.headers.get("x-role") or "system"
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and auth.count(".") >= 2:
        try:
            payload_part = auth.split(" ", 1)[1].split(".")[1]
            payload_part += "=" * (-len(payload_part) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_part.encode("utf-8")))
            user_id = str(claims.get("sub") or claims.get("user_id") or user_id)
            role = str(claims.get("role") or claims.get("roles") or role)
        except Exception:
            pass
    if body_text:
        try:
            payload = json.loads(body_text)
            user_id = str(payload.get("user_id") or payload.get("username") or payload.get("id") or user_id)
            role = str(payload.get("role") or role)
        except Exception:
            pass
    return user_id, role


def _failed_login_signal(path: str, body_text: str) -> tuple[bool, str | None]:
    target = None
    failed = False
    if body_text:
        try:
            payload = json.loads(body_text)
            target = str(payload.get("user_id") or payload.get("username") or payload.get("id") or "")
            event_type = str(payload.get("event_type") or "").lower()
            success = payload.get("success")
            failed = event_type == "login" and success is False
        except Exception:
            lowered = body_text.lower()
            failed = "login" in path.lower() and ("success=false" in lowered or "invalid" in lowered)
    return failed, target or None


def _captured_text(request: Request, body_text: str) -> str:
    query = str(request.url.query or "")
    decoded_query = str(request.query_params)
    return " ".join([request.url.path, query, decoded_query, body_text])


def _headers_size(request: Request) -> int:
    return sum(len(k) + len(v) + 4 for k, v in request.headers.items())


def _signal_to_event(
    *,
    request: Request,
    ip: str,
    method: str,
    path: str,
    status_code: int,
    latency_ms: float,
    response_size: int,
    request_size: int,
    header_size: int,
    body_size: int,
    body_text: str,
    user_agent: str,
    user_id: str,
    role: str,
    signal: SignatureMatch | RateSignal,
    source: str,
) -> TelemetryEvent:
    now = datetime.now(timezone.utc)
    technique_id = signal.technique_id
    event_type = signal.event_type
    return TelemetryEvent(
        event_id=f"LIVE-{event_type}-{int(now.timestamp() * 1000)}-{random.randint(1000, 9999)}",
        timestamp=now,
        user_id=user_id,
        role=role,
        device_id=f"IP-{ip}",
        segment="perimeter",
        ip=ip,
        event_type=event_type,
        success=False,
        latency_ms=round(max(latency_ms, 0.01), 2),
        bytes_out=response_size,
        label="live_perimeter",
        attack_id="LIVE-TRAFFIC",
        technique_id=technique_id,
        metadata={
            "source": source,
            "detection_layer": "perimeter",
            "technique_id": technique_id,
            "signal_family": getattr(signal, "family", "behavioral_rate"),
            "confidence": signal.confidence,
            "reason": signal.reason,
            "route": path,
            "method": method,
            "status_code": status_code,
            "client_ip": ip,
            "user_agent": user_agent,
            "query_params": dict(request.query_params),
            "body_excerpt": body_text[:1200],
            "request_size": request_size,
            "header_size": header_size,
            "body_size": body_size,
            "response_size": response_size,
            "blocked": GLOBAL_BLOCKLIST.is_blocked(ip),
        },
    )


def _block_ip_once(ip: str, signal: SignatureMatch | RateSignal, request_id: str) -> dict:
    if GLOBAL_BLOCKLIST.is_blocked(ip):
        return next((entry for entry in GLOBAL_BLOCKLIST.snapshot() if entry["ip"] == ip), {})
    entry = GLOBAL_BLOCKLIST.block(
        ip,
        technique_id=signal.technique_id,
        reason=signal.reason,
        confidence=signal.confidence,
    )
    audit.append(
        actor="perimeter_middleware",
        action="block_ip",
        justification=f"Blocked {ip}: {signal.reason} mapped to {signal.technique_id}",
        blast_radius=2,
        payload={
            **entry,
            "request_event_id": request_id,
            "event_type": signal.event_type,
            "family": getattr(signal, "family", "behavioral_rate"),
        },
    )
    return entry


def _block_alert_source(alert: Alert, actor: str, reason: str | None = None) -> dict:
    ip = alert.event.ip
    technique = alert.attribution.techniques[0].id
    if GLOBAL_BLOCKLIST.is_blocked(ip):
        entry = next((row for row in GLOBAL_BLOCKLIST.snapshot() if row["ip"] == ip), {})
    else:
        entry = GLOBAL_BLOCKLIST.block(
            ip,
            technique_id=technique,
            reason=reason or f"Live alert {alert.alert_id} exceeded behavioural containment threshold.",
            confidence=alert.attribution.confidence,
        )
        audit.append(
            actor=actor,
            action="block_ip",
            justification=f"Blocked {ip} for alert {alert.alert_id} mapped to {technique}.",
            blast_radius=2,
            payload={**entry, "alert_id": alert.alert_id, "event_id": alert.event.event_id, "universal_live_containment": True},
        )
    alert.event.metadata = {
        **alert.event.metadata,
        "active_mitigation": {
            "blocked": True,
            "ip": ip,
            "technique_id": technique,
            "expires_at": entry.get("expires_at"),
            "actor": actor,
        },
    }
    alert.status = "queued" if alert.severity in {"high", "critical"} else "contained"
    upsert_alert(alert.model_dump())
    write_json(ALERTS_PATH, [a.model_dump() for a in ALERTS])
    return entry


def _should_block(signal: SignatureMatch | RateSignal) -> bool:
    if isinstance(signal, SignatureMatch):
        return signal.block_immediately and signal.confidence >= 0.85
    return signal.confidence >= 0.82


@app.middleware("http")
async def live_request_detection_middleware(request: Request, call_next):
    start = time.perf_counter()
    path = request.url.path
    ip = client_ip(request)
    if _allow_local_blocked_soc_read(request, ip, path):
        return await call_next(request)
    if GLOBAL_BLOCKLIST.is_blocked(ip) and not _allow_local_blocked_soc_read(request, ip, path):
        body = await request.body()
        body_text = _maybe_parse_body(body, request.headers.get("content-type", ""))
        header_size = _headers_size(request)
        request_size = header_size + len(body) + len(str(request.url.query or ""))
        user_agent = request.headers.get("user-agent", "")
        user_id, role = _extract_auth_context(request, body_text)
        request_text = _captured_text(request, body_text)
        signature_matches = [
            match for match in scan_request(request_text, user_agent, header_size, len(body)) if match.family != "scanner_user_agent"
        ]
        audit.append(
            actor="perimeter_middleware",
            action="reject_blocked_ip",
            justification=f"Rejected blocked IP {ip} before route handling.",
            blast_radius=0,
            payload={"ip": ip, "route": path, "method": request.method},
        )
        if signature_matches:
            signal = signature_matches[0]
            event = _signal_to_event(
                request=request,
                ip=ip,
                method=request.method,
                path=path,
                status_code=403,
                latency_ms=(time.perf_counter() - start) * 1000,
                response_size=len(DENY_MESSAGE.encode("utf-8")),
                request_size=request_size,
                header_size=header_size,
                body_size=len(body),
                body_text=body_text,
                user_agent=user_agent,
                user_id=user_id,
                role=role,
                signal=signal,
                source="live_traffic",
            )
            event.metadata["repeat_blocked_attack"] = True
            result = process_telemetry_event(event)
            if result.get("alert_id"):
                run_orchestrator_for_alert(result["alert_id"], "perimeter_middleware")
        return PlainTextResponse(DENY_MESSAGE, status_code=403)

    if any(path.startswith(prefix) for prefix in MIDDLEWARE_SKIP_PREFIXES):
        return await call_next(request)

    body = await request.body()
    _set_replay_body(request, body)
    body_text = _maybe_parse_body(body, request.headers.get("content-type", ""))
    user_agent = request.headers.get("user-agent", "")
    user_id, role = _extract_auth_context(request, body_text)
    failed_login, target_user_id = _failed_login_signal(path, body_text)
    header_size = _headers_size(request)
    request_size = header_size + len(body) + len(str(request.url.query or ""))
    request_text = _captured_text(request, body_text)
    signature_matches = scan_request(request_text, user_agent, header_size, len(body))
    rate_result = GLOBAL_RATE_TRACKER.record_request(ip, path, failed_login, target_user_id)
    supporting_scanner_only = signature_matches and all(match.family == "scanner_user_agent" for match in signature_matches)
    signals: list[SignatureMatch | RateSignal] = []
    if not supporting_scanner_only:
        signals.extend(signature_matches)
    signals.extend(rate_result["signals"])

    pre_handler_block = next((signal for signal in signals if _should_block(signal)), None)
    if pre_handler_block:
        latency_ms = (time.perf_counter() - start) * 1000
        event = _signal_to_event(
            request=request,
            ip=ip,
            method=request.method,
            path=path,
            status_code=403,
            latency_ms=latency_ms,
            response_size=len(DENY_MESSAGE.encode("utf-8")),
            request_size=request_size,
            header_size=header_size,
            body_size=len(body),
            body_text=body_text,
            user_agent=user_agent,
            user_id=user_id,
            role=role,
            signal=pre_handler_block,
            source="live_traffic",
        )
        result = process_telemetry_event(event)
        _block_ip_once(ip, pre_handler_block, event.event_id)
        if result.get("alert_id"):
            run_orchestrator_for_alert(result["alert_id"], "perimeter_middleware")
        return PlainTextResponse(DENY_MESSAGE, status_code=403)

    response = await call_next(request)
    latency_ms = (time.perf_counter() - start) * 1000
    response_size = int(response.headers.get("content-length") or 0)
    for signal in signals:
        event = _signal_to_event(
            request=request,
            ip=ip,
            method=request.method,
            path=path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            response_size=response_size,
            request_size=request_size,
            header_size=header_size,
            body_size=len(body),
            body_text=body_text,
            user_agent=user_agent,
            user_id=user_id,
            role=role,
            signal=signal,
            source="live_traffic",
        )
        result = process_telemetry_event(event)
        if result.get("alert_id"):
            run_orchestrator_for_alert(result["alert_id"], "perimeter_middleware")
        if _should_block(signal):
            _block_ip_once(ip, signal, event.event_id)
    return response


@app.on_event("startup")
async def startup() -> None:
    ensure_dirs()
    init_db()
    global EVENTS, ALERTS, DEMO_TASK, DEMO_NORMAL_POOL, GENAI_WARMUP_TASK
    EVENTS = _load_events()
    anomaly_agent.fit(EVENTS)
    risk_agent.fit(EVENTS)
    ALERTS = _load_alerts()
    if not ALERTS:
        ALERTS = build_alerts(EVENTS, anomaly_agent, attribution_agent)
        write_json(ALERTS_PATH, [a.model_dump() for a in ALERTS])
    refresh_nvd_cache(force=False)
    if attribution_agent.genai.available():
        GENAI_WARMUP_TASK = asyncio.create_task(asyncio.to_thread(attribution_agent.genai.warm_up))
    sync_events([event.model_dump() for event in EVENTS])
    sync_alerts([alert.model_dump() for alert in ALERTS])
    if settings.demo_background_enabled:
        DEMO_NORMAL_POOL = [event for event in generate_events() if event.label == "normal"]
    if settings.demo_background_enabled and (DEMO_TASK is None or DEMO_TASK.done()):
        DEMO_TASK = asyncio.create_task(background_demo_traffic())


@app.on_event("shutdown")
async def shutdown() -> None:
    global DEMO_TASK, GENAI_WARMUP_TASK
    if GENAI_WARMUP_TASK and not GENAI_WARMUP_TASK.done():
        GENAI_WARMUP_TASK.cancel()
    GENAI_WARMUP_TASK = None
    if DEMO_TASK:
        DEMO_TASK.cancel()
        try:
            await DEMO_TASK
        except asyncio.CancelledError:
            pass
        DEMO_TASK = None


@app.get("/health")
def health() -> dict:
    return {"ok": True, "events": len(EVENTS), "alerts": len(ALERTS)}


@app.get("/ready")
def ready() -> dict:
    return {
        "ok": True,
        "database": db_health(),
        "anomaly_model_fit": anomaly_agent._fit,
        "predictive_risk_model_fit": risk_agent._fit,
        "predictive_risk_threshold": settings.predictive_risk_threshold,
        "genai_attribution": {
            "provider": settings.genai_provider,
            "configured": attribution_agent.genai.available(),
            "model": settings.genai_model if attribution_agent.genai.available() else "offline-fallback",
        },
        "mitre_techniques": len(attribution_agent.retriever.techniques),
        "demo_traffic": demo_status(),
        "blocked_ips": GLOBAL_BLOCKLIST.snapshot(),
    }


@app.post("/ingest/events", status_code=202)
def ingest_event(raw: RawEvent, request: Request, _: None = Depends(check_ingest_rate_limit)) -> dict:
    return process_event(raw)


def process_event(raw: RawEvent) -> dict:
    event = normalize_frontend_event(raw)
    return process_telemetry_event(event)


def process_telemetry_event(event: TelemetryEvent) -> dict:
    history = EVENTS[-500:]
    score = anomaly_agent.score(event)
    risk_prediction = (
        risk_agent.predict(event, history)
        if risk_agent._fit
        else RiskPrediction(score=0.0, attack_probability=0.0, sequence_surprise=0.0, entity_pressure=0.0, confidence=0.0)
    )
    risk_payload = asdict(risk_prediction)
    decision_score = max(score, risk_prediction.score)
    event.metadata = {
        **event.metadata,
        "model_scores": {
            "anomaly_score": round(score, 3),
            "predictive_risk_score": risk_prediction.score,
            "decision_score": round(decision_score, 3),
        },
        "prediction": risk_payload,
    }
    EVENTS.append(event)
    append_jsonl(EVENTS_PATH, event.model_dump())
    upsert_event(event.model_dump())
    audit.append(
        actor="ingest_pipeline",
        action="score_event",
        justification=f"Telemetry event {event.event_id} scored through anomaly and predictive-risk pipelines.",
        blast_radius=0,
        payload={
            "event_id": event.event_id,
            "score": round(score, 3),
            "predictive_risk_score": risk_prediction.score,
            "decision_score": round(decision_score, 3),
            "label": event.label,
            "source": event.metadata.get("source"),
            "risk_reasons": risk_prediction.reasons,
        },
    )
    alert_id = None
    if score >= anomaly_agent.threshold or risk_prediction.score >= risk_agent.threshold:
        alert_id = f"ALT-{len(ALERTS) + 1:05d}"
        attribution = attribution_agent.attribute(alert_id, event, decision_score, risk=risk_payload)
        ALERTS.insert(
            0,
            Alert(
                alert_id=alert_id,
                event=event,
                anomaly_score=round(decision_score, 3),
                severity=severity_for(decision_score),
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
            justification=(
                "Event exceeded behavioural decision threshold "
                f"(anomaly={score:.2f}, predictive_risk={risk_prediction.score:.2f})."
            ),
            blast_radius=1,
            payload={"event_id": event.event_id, "alert_id": alert_id},
        )
        if event.metadata.get("source") == "live_traffic":
            _block_alert_source(
                ALERTS[0],
                actor="active_containment",
                reason="Universal live-attack containment: any detected live attack is blocked at the source.",
            )
    return {
        "accepted": True,
        "score": round(score, 3),
        "predictive_risk_score": risk_prediction.score,
        "decision_score": round(decision_score, 3),
        "alert_id": alert_id,
    }


def run_orchestrator_for_alert(alert_id: str, actor: str) -> None:
    alert = next((row for row in ALERTS if row.alert_id == alert_id), None)
    if not alert:
        return
    run = orchestrator_agent.run(alert)
    alert.status = "queued" if run.status == "queued_for_approval" else "contained"
    if alert.event.metadata.get("source") == "live_traffic":
        _block_alert_source(alert, actor=actor, reason=f"SOAR playbook containment for {alert_id}.")
    upsert_alert(alert.model_dump())
    write_json(ALERTS_PATH, [a.model_dump() for a in ALERTS])
    audit.append(
        actor=actor,
        action="orchestrate_perimeter_response",
        justification=f"Existing orchestrator_agent processed alert {alert_id} from live request detection.",
        blast_radius=0,
        payload={"alert_id": alert_id, "run_id": run.run_id, "status": run.status},
    )


def _alert_by_id(alert_id: str) -> Alert | None:
    return next((row for row in ALERTS if row.alert_id == alert_id), None)


def _coverage_status(technique_id: str) -> tuple[str, str]:
    base_id = technique_id.split(".", 1)[0]
    if technique_id in ACTIVE_LIVE_TECHNIQUES or base_id in ACTIVE_LIVE_TECHNIQUES:
        return "active_live", ACTIVE_LIVE_TECHNIQUES.get(technique_id) or ACTIVE_LIVE_TECHNIQUES[base_id]
    connector_map = {
        "T1003": "Requires EDRConnector for credential dumping telemetry.",
        "T1021": "Requires SIEM/EDR/IAM connectors for real lateral movement telemetry.",
        "T1041": "Requires proxy/DNS/firewall telemetry for C2 exfiltration.",
        "T1055": "Requires EDRConnector for process injection visibility.",
        "T1070": "Requires EDR/SIEM log tampering telemetry.",
        "T1078": "Requires IAMConnector for real valid-account abuse containment.",
        "T1098": "Requires IAM/CloudAudit connectors for account manipulation.",
        "T1105": "Requires firewall/proxy telemetry for ingress transfer.",
        "T1562": "Requires EDR/SIEM security-control health telemetry.",
        "T1567": "Requires proxy/CASB/cloud telemetry for cloud exfiltration.",
    }
    if base_id in connector_map:
        return "needs_connector", connector_map[base_id]
    return "attribution_ready", "Loaded in ATT&CK corpus for RAG/GenAI attribution and safe simulation."


def _timeline_for_alert(alert: Alert) -> list[dict]:
    event = alert.event
    scores = event.metadata.get("model_scores", {}) if event.metadata else {}
    timeline = [
        {
            "stage": "observed",
            "timestamp": event.timestamp,
            "title": f"{event.event_type} observed",
            "detail": f"{event.ip} hit {event.metadata.get('method', 'event')} {event.metadata.get('route', event.segment)}",
            "status": "complete",
        },
        {
            "stage": "scored",
            "timestamp": alert.created_at,
            "title": "AI scoring completed",
            "detail": (
                f"decision={scores.get('decision_score', alert.anomaly_score)}, "
                f"anomaly={scores.get('anomaly_score', alert.anomaly_score)}, "
                f"predictive={scores.get('predictive_risk_score', 'n/a')}"
            ),
            "status": "complete",
        },
        {
            "stage": "attributed",
            "timestamp": alert.created_at,
            "title": f"Mapped to {alert.attribution.techniques[0].id}",
            "detail": alert.attribution.likely_next_stage,
            "status": "complete",
        },
    ]
    related = []
    for entry in reversed(audit.entries(limit=500)):
        payload = entry.payload or {}
        if payload.get("alert_id") == alert.alert_id or payload.get("event_id") == event.event_id or payload.get("request_event_id") == event.event_id:
            related.append(
                {
                    "stage": "audit",
                    "timestamp": entry.timestamp,
                    "title": entry.action,
                    "detail": entry.justification,
                    "status": "queued" if "queue" in entry.action else "complete",
                    "actor": entry.actor,
                    "hash": entry.hash,
                }
            )
    return sorted([*timeline, *related], key=lambda item: str(item["timestamp"]))


def _copilot_answer(question: str, alert: Alert | None) -> dict:
    q = question.lower()
    if not alert:
        live_count = len([row for row in ALERTS if row.event.metadata.get("source") == "live_traffic"])
        fallback = {
            "answer": (
                f"There are {live_count} live incidents in the current SOC feed. "
                "Ask about a selected alert to get technique, risk, containment, and audit context."
            ),
            "evidence": ["No alert_id was supplied.", "Responses are defensive summaries only."],
            "recommended_actions": ["Select an alert", "Review ATT&CK coverage", "Verify audit chain"],
            "provider": "offline",
        }
        return attribution_agent.genai.answer_copilot(
            question=question,
            context={"live_incident_count": live_count, "selected_alert": None},
            fallback=fallback,
        )
    scores = alert.event.metadata.get("model_scores", {}) if alert.event.metadata else {}
    prediction = alert.event.metadata.get("prediction", {}) if alert.event.metadata else {}
    primary = alert.attribution.techniques[0]
    if "why" in q or "explain" in q:
        answer = (
            f"{alert.alert_id} was raised because {alert.event.event_type} on {alert.event.segment} exceeded the decision threshold. "
            f"The primary ATT&CK mapping is {primary.id} {primary.name}. "
            f"The predictive model's likely next stage is {prediction.get('predicted_next_stage', alert.attribution.likely_next_stage)}."
        )
    elif "mitigat" in q or "contain" in q or "block" in q:
        answer = (
            f"Containment is already staged for {alert.alert_id}: block the source {alert.event.ip}, preserve evidence, "
            "revoke exposed sessions when identity abuse is involved, and require approval for high-blast-radius endpoint isolation."
        )
    elif "next" in q or "predict" in q:
        answer = (
            f"The most likely next stage is {prediction.get('predicted_next_stage', alert.attribution.likely_next_stage)}. "
            "Prioritise controls that break that path before expanding containment."
        )
    else:
        answer = (
            f"{alert.alert_id}: {primary.id} {primary.name}, severity {alert.severity}, status {alert.status}. "
            f"Decision score {scores.get('decision_score', alert.anomaly_score)}."
        )
    fallback = {
        "answer": answer,
        "evidence": alert.attribution.evidence[:6],
        "recommended_actions": [
            "Confirm 403 enforcement for the source IP",
            "Run or review the generated SOAR playbook",
            "Check hash-chain audit verification",
            "Review CVE queue for assets related to the observed ATT&CK technique",
        ],
        "provider": "offline",
    }
    context = {
        "alert_id": alert.alert_id,
        "event_type": alert.event.event_type,
        "severity": alert.severity,
        "status": alert.status,
        "source_ip": alert.event.ip,
        "technique": primary.model_dump(),
        "scores": scores,
        "prediction": prediction,
        "attribution_evidence": alert.attribution.evidence[:6],
        "recommendation": alert.attribution.recommendation,
    }
    return attribution_agent.genai.answer_copilot(question=question, context=context, fallback=fallback)


def clone_demo_benign_event(template: TelemetryEvent) -> TelemetryEvent:
    now = datetime.now(timezone.utc)
    return template.model_copy(
        update={
            "event_id": f"DEMO-BENIGN-{int(now.timestamp() * 1000)}-{random.randint(1000, 9999)}",
            "timestamp": template.timestamp,
            "label": "normal",
            "attack_id": None,
            "technique_id": None,
            "metadata": {
                **template.metadata,
                "source": "background_demo_traffic",
                "simulation": True,
                "safe": True,
            },
        }
    )


def next_demo_benign_event(rng: random.Random) -> TelemetryEvent | None:
    if not DEMO_NORMAL_POOL:
        return None
    candidate = clone_demo_benign_event(rng.choice(DEMO_NORMAL_POOL))
    for _ in range(12):
        if anomaly_agent.score(candidate) < anomaly_agent.threshold:
            return candidate
        candidate = clone_demo_benign_event(rng.choice(DEMO_NORMAL_POOL))
    return candidate


def build_demo_attack_event(idx: int) -> TelemetryEvent:
    technique_id = random.choice(DEMO_ATTACK_TECHNIQUES)
    technique = find_technique(technique_id)
    raw = build_attack_event(technique, idx, 1)
    event = normalize_frontend_event(RawEvent.model_validate(raw))
    return event.model_copy(
        update={
            "event_id": f"DEMO-ATTACK-{technique_id}-{int(event.timestamp.timestamp() * 1000)}-{random.randint(1000, 9999)}",
            "label": "background_attack_simulation",
            "attack_id": "DEMO-BACKGROUND",
            "technique_id": technique_id,
            "metadata": {
                **event.metadata,
                "source": "background_demo_traffic",
                "simulation": True,
                "safe": True,
                "background": True,
            },
        }
    )


async def background_demo_traffic() -> None:
    global DEMO_PAUSED
    rng = random.Random()
    next_attack_in = rng.uniform(45, 90)
    seconds_until_attack = next_attack_in
    attack_idx = 1
    while True:
        delay = rng.uniform(3, 8)
        await asyncio.sleep(delay)
        if DEMO_PAUSED:
            continue
        seconds_until_attack -= delay
        if seconds_until_attack <= 0:
            event = build_demo_attack_event(attack_idx)
            result = process_telemetry_event(event)
            DEMO_STATS["attack_events"] += 1
            DEMO_STATS["last_event"] = event.event_id
            DEMO_STATS["last_alert_id"] = result.get("alert_id")
            attack_idx += 1
            seconds_until_attack = rng.uniform(45, 90)
            continue
        event = next_demo_benign_event(rng)
        if event:
            result = process_telemetry_event(event)
            DEMO_STATS["benign_events"] += 1
            DEMO_STATS["last_event"] = event.event_id
            DEMO_STATS["last_alert_id"] = result.get("alert_id")


def demo_status() -> dict:
    return {
        "enabled": settings.demo_background_enabled,
        "paused": DEMO_PAUSED,
        "task_running": DEMO_TASK is not None and not DEMO_TASK.done(),
        **DEMO_STATS,
    }


@app.post("/demo/pause", dependencies=[OperatorAuth])
def pause_demo() -> dict:
    global DEMO_PAUSED
    DEMO_PAUSED = True
    audit.append(
        actor="security_operator",
        action="pause_background_demo_traffic",
        justification="Operator paused autonomous background demo traffic.",
        blast_radius=0,
        payload=demo_status(),
    )
    return demo_status()


@app.post("/demo/resume", dependencies=[OperatorAuth])
async def resume_demo() -> dict:
    global DEMO_PAUSED, DEMO_TASK, DEMO_NORMAL_POOL
    if not settings.demo_background_enabled:
        DEMO_PAUSED = False
        return demo_status()
    if not DEMO_NORMAL_POOL:
        DEMO_NORMAL_POOL = [event for event in generate_events() if event.label == "normal"]
    if DEMO_TASK is None or DEMO_TASK.done():
        DEMO_TASK = asyncio.create_task(background_demo_traffic())
    DEMO_PAUSED = False
    audit.append(
        actor="security_operator",
        action="resume_background_demo_traffic",
        justification="Operator resumed autonomous background demo traffic.",
        blast_radius=0,
        payload=demo_status(),
    )
    return demo_status()


@app.get("/demo/status")
def get_demo_status() -> dict:
    return demo_status()


@app.get("/blocks")
def get_blocks() -> dict:
    return {"items": GLOBAL_BLOCKLIST.snapshot(), "total": len(GLOBAL_BLOCKLIST.snapshot())}


@app.post("/blocks/{ip}/unblock", dependencies=[OperatorAuth])
def unblock_ip(ip: str) -> dict:
    entry = GLOBAL_BLOCKLIST.unblock(ip)
    audit.append(
        actor="security_operator",
        action="unblock_ip",
        justification=f"Operator removed block for {ip}.",
        blast_radius=1,
        payload={"ip": ip, "previous_entry": entry},
    )
    return {"removed": entry is not None, "ip": ip}


@app.post("/alerts/{alert_id}/block-source", dependencies=[OperatorAuth])
def block_alert_source(alert_id: str) -> dict:
    alert = _alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    entry = _block_alert_source(alert, actor="security_operator", reason=f"Operator manually blocked source for {alert_id}.")
    return {"blocked": True, "entry": entry, "alert": alert.model_dump()}


@app.post("/simulate/attack/{technique_id}", dependencies=[OperatorAuth])
def simulate_attack(technique_id: str, count: int = Query(8, ge=1, le=30)) -> dict:
    try:
        technique = find_technique(technique_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Technique not found in local ATT&CK corpus")
    results = []
    for idx in range(1, count + 1):
        event = normalize_frontend_event(RawEvent.model_validate(build_attack_event(technique, idx, count)))
        event = event.model_copy(update={"label": "manual_attack_simulation", "attack_id": "MANUAL-SIMULATION", "technique_id": technique["id"]})
        result = process_telemetry_event(event)
        results.append(result)
    audit.append(
        actor="attack_simulator",
        action="run_safe_attack_simulation",
        justification=f"Operator triggered safe telemetry simulation for {technique['id']} {technique['name']}.",
        blast_radius=0,
        payload={"technique_id": technique["id"], "count": count, "alerts": [r.get("alert_id") for r in results if r.get("alert_id")]},
    )
    return {"technique": technique, "results": results}


@app.get("/alerts")
def get_alerts(
    severity: str | None = None,
    technique: str | None = None,
    source: str | None = "live_traffic",
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    rows = ALERTS
    if source and source != "all":
        rows = [alert for alert in rows if alert.event.metadata.get("source") == source]
    if severity:
        rows = [alert for alert in rows if alert.severity == severity]
    if technique:
        rows = [alert for alert in rows if any(t.id == technique for t in alert.attribution.techniques)]
    return {"items": [alert.model_dump() for alert in rows[:limit]], "total": len(rows)}


@app.get("/alerts/stream")
async def alert_stream(source: str | None = "live_traffic") -> EventSourceResponse:
    async def generator():
        sent: set[str] = set()
        while True:
            for alert in reversed(ALERTS):
                if alert.alert_id in sent:
                    continue
                if source and source != "all" and alert.event.metadata.get("source") != source:
                    continue
                sent.add(alert.alert_id)
                yield {"event": "alert", "data": json.dumps(alert.model_dump(), default=str)}
            await asyncio.sleep(2)

    return EventSourceResponse(generator())


@app.get("/attribution/{alert_id}")
def get_attribution(alert_id: str) -> dict:
    alert = next((row for row in ALERTS if row.alert_id == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.attribution.model_dump()


@app.get("/coverage/mitre")
def mitre_coverage() -> dict:
    techniques = attribution_agent.retriever.techniques
    by_tactic: dict[str, dict] = {}
    rows = []
    for technique in techniques:
        status, reason = _coverage_status(technique.id)
        tactics = technique.tactics or ["uncategorized"]
        rows.append(
            {
                "id": technique.id,
                "name": technique.name,
                "tactics": tactics,
                "status": status,
                "reason": reason,
                "url": technique.url,
            }
        )
        for tactic in tactics:
            bucket = by_tactic.setdefault(
                tactic,
                {"tactic": tactic, "total": 0, "active_live": 0, "attribution_ready": 0, "needs_connector": 0},
            )
            bucket["total"] += 1
            bucket[status] = bucket.get(status, 0) + 1
    return {
        "summary": {
            "total": len(rows),
            "active_live": sum(1 for row in rows if row["status"] == "active_live"),
            "attribution_ready": sum(1 for row in rows if row["status"] == "attribution_ready"),
            "needs_connector": sum(1 for row in rows if row["status"] == "needs_connector"),
            "connectors": len(connector_catalog()),
        },
        "tactics": sorted(by_tactic.values(), key=lambda row: row["tactic"]),
        "techniques": rows,
    }


@app.get("/prevention/zero-day")
def zero_day_prevention() -> dict:
    return zero_day_prevention_strategy()


@app.get("/incidents/{alert_id}/timeline")
def incident_timeline(alert_id: str) -> dict:
    alert = _alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_id": alert_id, "items": _timeline_for_alert(alert)}


@app.get("/integrations/connectors")
def integrations_connectors() -> dict:
    return {"items": connector_catalog()}


@app.post("/copilot/ask")
def ask_copilot(question: CopilotQuestion) -> dict:
    alert = _alert_by_id(question.alert_id) if question.alert_id else None
    answer = _copilot_answer(question.question, alert)
    audit.append(
        actor="soc_copilot",
        action="answer_operator_question",
        justification="Generated defensive SOC copilot summary from local alert context.",
        blast_radius=0,
        payload={"alert_id": question.alert_id, "question": question.question[:240]},
    )
    return answer


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
def cve_queue(source: str | None = "live_traffic") -> dict:
    rows = ALERTS
    if source and source != "all":
        rows = [alert for alert in rows if alert.event.metadata.get("source") == source]
    observed = [alert.attribution.techniques[0].id for alert in rows]
    if source and source != "all" and not observed:
        return {"items": []}
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
