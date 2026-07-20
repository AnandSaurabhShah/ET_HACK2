from __future__ import annotations

from typing import Any

from app.agents.genai_attribution import GenAIAttributionProvider
from app.models.schemas import Attribution, MitreTechnique, TelemetryEvent
from app.rag.mitre_loader import TechniqueRetriever


class AttributionAgent:
    def __init__(self, retriever: TechniqueRetriever | None = None, genai: GenAIAttributionProvider | None = None) -> None:
        self.retriever = retriever or TechniqueRetriever()
        self.genai = genai or GenAIAttributionProvider()

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

    def attribute(self, alert_id: str, event: TelemetryEvent, score: float, risk: dict[str, Any] | None = None) -> Attribution:
        known = self.retriever.get(event.technique_id or "")
        techniques = [known] if known else []
        if not techniques:
            techniques = self.retriever.query(self._query_text(event), limit=3)
        if not techniques:
            techniques = [self.retriever.get("T1078")].copy()
        techniques = [t for t in techniques if t is not None]
        primary = techniques[0]
        draft = self.genai.generate(event=event, score=score, techniques=techniques[:3], risk=risk)
        provider_note = f"GenAI attribution provider: {draft.provider}"
        return Attribution(
            alert_id=alert_id,
            techniques=techniques[:3],
            confidence=round(min(0.96, 0.58 + score * 0.35 + (0.08 if known else 0)), 2),
            evidence=[*draft.evidence, provider_note],
            likely_next_stage=draft.likely_next_stage,
            recommendation=draft.recommendation,
        )
