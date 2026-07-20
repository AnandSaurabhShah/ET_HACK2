from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from app.config import get_settings
from app.models.schemas import MitreTechnique, TelemetryEvent


@dataclass(frozen=True)
class AttributionDraft:
    evidence: list[str] = field(default_factory=list)
    likely_next_stage: str = "credential validation and lateral movement"
    recommendation: str = "Apply relevant ATT&CK mitigations, contain the source, and preserve forensic evidence."
    provider: str = "offline"


class GenAIAttributionProvider:
    def __init__(self) -> None:
        self.settings = get_settings()

    def available(self) -> bool:
        return self.settings.genai_provider.lower() not in {"", "offline", "disabled"} and bool(self.settings.genai_api_key)

    def _offline(
        self,
        event: TelemetryEvent,
        score: float,
        techniques: list[MitreTechnique],
        risk: dict | None,
        reason: str | None = None,
    ) -> AttributionDraft:
        primary = techniques[0]
        mitigations = primary.mitigations[:3] or ["tighten compensating controls", "preserve logs", "review exposed services"]
        predicted = (risk or {}).get("predicted_next_stage")
        likely_next_stage = predicted or {
            "credential-access": "valid-account abuse against privileged roles",
            "initial-access": "session establishment followed by persistence",
            "lateral-movement": "movement from exposed service toward privileged internal systems",
            "exfiltration": "bulk data staging and outbound transfer",
            "impact": "availability degradation or service interruption",
        }.get(primary.tactics[0] if primary.tactics else "", "credential validation and lateral movement")
        evidence = [
            f"Observed event={event.event_type}, segment={event.segment}, score={score:.2f}",
            f"Primary ATT&CK match {primary.id}: {primary.name}",
        ]
        if risk:
            evidence.append(
                "Predictive risk model: "
                f"score={risk.get('score')}, attack_probability={risk.get('attack_probability')}, "
                f"sequence_surprise={risk.get('sequence_surprise')}"
            )
            evidence.extend([str(item) for item in risk.get("reasons", [])[:3]])
        if reason:
            evidence.append(f"GenAI fallback reason: {reason}")
        return AttributionDraft(
            evidence=evidence,
            likely_next_stage=str(likely_next_stage),
            recommendation=(
                f"Defensive response for {primary.id} ({primary.name}): "
                f"{'; '.join(mitigations)}. Contain source IP/session, preserve evidence, "
                "and require approval for high-blast-radius actions."
            ),
            provider="offline",
        )

    def generate(
        self,
        *,
        event: TelemetryEvent,
        score: float,
        techniques: list[MitreTechnique],
        risk: dict | None,
    ) -> AttributionDraft:
        if not techniques:
            return AttributionDraft()
        if not self.available():
            return self._offline(event, score, techniques, risk)

        primary = techniques[0]
        prompt = {
            "task": "Generate defensive SOC attribution only. Do not provide exploit steps or offensive instructions.",
            "event": {
                "event_type": event.event_type,
                "segment": event.segment,
                "role": event.role,
                "success": event.success,
                "metadata": event.metadata,
            },
            "score": score,
            "predictive_risk": risk or {},
            "techniques": [
                {"id": t.id, "name": t.name, "tactics": t.tactics, "mitigations": t.mitigations[:5]}
                for t in techniques[:3]
            ],
            "required_json_keys": ["evidence", "likely_next_stage", "recommendation"],
        }
        payload = {
            "model": self.settings.genai_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a defensive cyber SOC attribution analyst. "
                        "Return strict JSON only. Keep recommendations defensive, auditable, and non-offensive."
                    ),
                },
                {"role": "user", "content": json.dumps(prompt, default=str)},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            self.settings.genai_endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.settings.genai_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.genai_timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            evidence = parsed.get("evidence") or []
            return AttributionDraft(
                evidence=[str(item) for item in evidence][:8],
                likely_next_stage=str(parsed.get("likely_next_stage") or "credential validation and lateral movement"),
                recommendation=str(
                    parsed.get("recommendation")
                    or f"Apply mitigations for {primary.id} and execute approved containment."
                ),
                provider=self.settings.genai_provider,
            )
        except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError) as exc:
            return self._offline(event, score, techniques, risk, reason=str(exc))
