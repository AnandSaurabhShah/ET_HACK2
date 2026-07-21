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
        provider = self.settings.genai_provider.lower()
        if provider == "ollama":
            return bool(self.settings.genai_endpoint and self.settings.genai_model)
        return provider not in {"", "offline", "disabled"} and bool(self.settings.genai_api_key)

    def _system_prompt(self) -> str:
        return (
            "You are Aegis-CNI, a defensive GenAI SOC analyst for Indian critical exam infrastructure. "
            "Return strict JSON only. Use MITRE ATT&CK evidence, predictive-risk signals, and audit-aware recommendations. "
            "Never provide exploit instructions, payload construction, malware steps, credential theft steps, or offensive playbooks. "
            "Focus on detection explanation, likely next-stage prediction, containment, verification, and recovery."
        )

    def _prompt(
        self,
        *,
        event: TelemetryEvent,
        score: float,
        techniques: list[MitreTechnique],
        risk: dict | None,
    ) -> dict:
        return {
            "task": "Generate defensive SOC attribution only.",
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

    def _draft_from_parsed(self, parsed: dict, provider: str, primary: MitreTechnique) -> AttributionDraft:
        evidence = parsed.get("evidence") or []
        return AttributionDraft(
            evidence=[str(item) for item in evidence][:8],
            likely_next_stage=str(parsed.get("likely_next_stage") or "credential validation and lateral movement"),
            recommendation=str(
                parsed.get("recommendation")
                or f"Apply mitigations for {primary.id} and execute approved containment."
            ),
            provider=provider,
        )

    def _generate_ollama(self, prompt: dict, primary: MitreTechnique) -> AttributionDraft:
        payload = {
            "model": self.settings.genai_model,
            "system": self._system_prompt(),
            "prompt": json.dumps(prompt, default=str),
            "stream": False,
            "format": "json",
            "keep_alive": "30m",
            "options": {"temperature": 0.15, "num_predict": 700},
        }
        request = urllib.request.Request(
            self.settings.genai_endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.settings.genai_timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
        parsed = json.loads(body.get("response") or "{}")
        return self._draft_from_parsed(parsed, f"ollama:{self.settings.genai_model}", primary)

    def warm_up(self) -> bool:
        if self.settings.genai_provider.lower() != "ollama" or not self.available():
            return False
        payload = {
            "model": self.settings.genai_model,
            "system": self._system_prompt(),
            "prompt": json.dumps({"task": "warm_up", "required_json_keys": ["ok"]}),
            "stream": False,
            "format": "json",
            "keep_alive": "30m",
            "options": {"temperature": 0.0, "num_predict": 32},
        }
        request = urllib.request.Request(
            self.settings.genai_endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        timeout = max(20.0, min(90.0, self.settings.genai_timeout_seconds * 8))
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            json.loads(body.get("response") or "{}")
            return True
        except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError):
            return False

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
        if event.metadata.get("source") == "live_traffic":
            return self._offline(
                event,
                score,
                techniques,
                risk,
                reason="Live request path prioritised low-latency containment; SOC Copilot uses Ollama for on-demand GenAI reasoning.",
            )
        if not self.available():
            return self._offline(event, score, techniques, risk)

        primary = techniques[0]
        prompt = self._prompt(event=event, score=score, techniques=techniques, risk=risk)
        if self.settings.genai_provider.lower() == "ollama":
            try:
                return self._generate_ollama(prompt, primary)
            except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError) as exc:
                return self._offline(event, score, techniques, risk, reason=f"Ollama unavailable or invalid JSON: {exc}")

        payload = {
            "model": self.settings.genai_model,
            "messages": [
                {
                    "role": "system",
                    "content": self._system_prompt(),
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
            return self._draft_from_parsed(parsed, self.settings.genai_provider, primary)
        except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError) as exc:
            return self._offline(event, score, techniques, risk, reason=str(exc))

    def answer_copilot(self, *, question: str, context: dict, fallback: dict) -> dict:
        if not self.available():
            return fallback
        prompt = {
            "task": "Answer a SOC operator question using only defensive incident context.",
            "question": question,
            "context": context,
            "required_json_keys": ["answer", "evidence", "recommended_actions"],
        }
        if self.settings.genai_provider.lower() == "ollama":
            payload = {
                "model": self.settings.genai_model,
                "system": self._system_prompt(),
                "prompt": json.dumps(prompt, default=str),
                "stream": False,
                "format": "json",
                "keep_alive": "30m",
                "options": {"temperature": 0.2, "num_predict": 600},
            }
            request = urllib.request.Request(
                self.settings.genai_endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.settings.genai_timeout_seconds) as response:
                    body = json.loads(response.read().decode("utf-8"))
                parsed = json.loads(body.get("response") or "{}")
                return {
                    "answer": str(parsed.get("answer") or fallback["answer"]),
                    "evidence": [str(item) for item in (parsed.get("evidence") or fallback["evidence"])][:8],
                    "recommended_actions": [
                        str(item) for item in (parsed.get("recommended_actions") or fallback["recommended_actions"])
                    ][:6],
                    "provider": f"ollama:{self.settings.genai_model}",
                }
            except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError) as exc:
                return {**fallback, "provider": "offline", "fallback_reason": f"Ollama unavailable or invalid JSON: {exc}"}
        return fallback
