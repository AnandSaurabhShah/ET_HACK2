from __future__ import annotations

from uuid import uuid4

from app.audit.audit_log import AuditLog
from app.models.schemas import Alert, PlaybookRun, PlaybookStep


class OrchestratorAgent:
    def __init__(self, audit: AuditLog | None = None, blast_threshold: int = 6) -> None:
        self.audit = audit or AuditLog()
        self.blast_threshold = blast_threshold
        self.runs: dict[str, PlaybookRun] = {}

    def steps_for(self, alert: Alert) -> list[PlaybookStep]:
        technique = alert.attribution.techniques[0].id
        steps = [
            PlaybookStep(name="Snapshot affected state", action="snapshot_state", blast_radius=1),
            PlaybookStep(name="Block source IP", action=f"block_ip:{alert.event.ip}", blast_radius=3),
        ]
        if technique in {"T1078", "T1110"}:
            steps.append(PlaybookStep(name="Revoke credential/session", action=f"revoke_session:{alert.event.user_id}", blast_radius=5))
        if alert.severity in {"high", "critical"}:
            steps.append(PlaybookStep(name="Isolate endpoint", action=f"isolate_endpoint:{alert.event.device_id}", blast_radius=8))
        return steps

    def run(self, alert: Alert) -> PlaybookRun:
        run_id = f"RUN-{uuid4().hex[:8].upper()}"
        steps = self.steps_for(alert)
        requires_approval = any(step.blast_radius > self.blast_threshold for step in steps)
        for step in steps:
            step.status = "queued" if step.blast_radius > self.blast_threshold else "executed"
            if step.status == "executed":
                self.audit.append(
                    actor="orchestrator_agent",
                    action=step.action,
                    justification=f"Containment for alert {alert.alert_id} mapped to {alert.attribution.techniques[0].id}",
                    blast_radius=step.blast_radius,
                    payload={"run_id": run_id, "alert_id": alert.alert_id},
                )
        if requires_approval:
            self.audit.append(
                actor="orchestrator_agent",
                action="queue_high_blast_radius_approval",
                justification=f"High-impact containment requires human approval for {alert.alert_id}",
                blast_radius=max(step.blast_radius for step in steps),
                payload={"run_id": run_id, "alert_id": alert.alert_id},
            )
        autonomous = sum(1 for step in steps if step.status == "executed") / len(steps) * 100
        run = PlaybookRun(
            run_id=run_id,
            alert_id=alert.alert_id,
            status="queued_for_approval" if requires_approval else "executed",
            steps=steps,
            justification=alert.attribution.recommendation,
            autonomous_percent=round(autonomous, 1),
        )
        self.runs[run_id] = run
        return run

    def approve(self, run_id: str) -> PlaybookRun | None:
        run = self.runs.get(run_id)
        if not run:
            return None
        for step in run.steps:
            if step.status == "queued":
                step.status = "approved"
                self.audit.append(
                    actor="security_operator",
                    action=step.action,
                    justification=f"Human-approved high-impact step in {run_id}",
                    blast_radius=step.blast_radius,
                    payload={"run_id": run_id, "alert_id": run.alert_id},
                )
        run.status = "approved"
        run.autonomous_percent = 100.0
        return run

