from __future__ import annotations

from app.models.schemas import Attribution, MitreTechnique, TelemetryEvent
from app.rag.mitre_loader import TechniqueRetriever


class AttributionAgent:
    def __init__(self, retriever: TechniqueRetriever | None = None) -> None:
        self.retriever = retriever or TechniqueRetriever()

    def _query_text(self, event: TelemetryEvent) -> str:
        return " ".join(
            [
                event.label,
                event.event_type,
                event.segment,
                "failed authentication brute force" if not event.success else "successful valid account",
                "high latency denial service" if event.latency_ms > 500 else "",
                "large outbound exfiltration collection" if event.bytes_out > 500 else "",
            ]
        )

    def attribute(self, alert_id: str, event: TelemetryEvent, score: float) -> Attribution:
        known = self.retriever.get(event.technique_id or "")
        techniques = [known] if known else []
        if not techniques:
            techniques = self.retriever.query(self._query_text(event), limit=3)
        if not techniques:
            techniques = [self.retriever.get("T1078")].copy()
        techniques = [t for t in techniques if t is not None]
        primary = techniques[0]
        mitigations = primary.mitigations[:3] or ["Review ATT&CK mitigation guidance and tighten compensating controls."]
        next_stage = {
            "credential-access": "valid-account abuse against privileged exam roles",
            "initial-access": "session establishment followed by persistence",
            "lateral-movement": "movement from marking portal toward auth DB",
            "exfiltration": "bulk script or certificate data staging",
            "impact": "availability degradation of certificate/exam services",
        }.get(primary.tactics[0] if primary.tactics else "", "credential validation and lateral movement")
        recommendation = (
            f"Apply mitigations for {primary.id} ({primary.name}): "
            f"{'; '.join(mitigations)}. Queue high-blast-radius containment for approval."
        )
        return Attribution(
            alert_id=alert_id,
            techniques=techniques[:3],
            confidence=round(min(0.96, 0.58 + score * 0.35 + (0.08 if known else 0)), 2),
            evidence=[
                f"Event type={event.event_type}, segment={event.segment}, score={score:.2f}",
                f"Retrieved ATT&CK technique {primary.id}: {primary.name}",
                "LLM reasoning provider: deterministic offline fallback",
            ],
            likely_next_stage=next_stage,
            recommendation=recommendation,
        )

