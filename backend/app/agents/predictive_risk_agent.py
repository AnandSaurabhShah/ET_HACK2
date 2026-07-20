from __future__ import annotations

import hashlib
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

from app.models.schemas import TelemetryEvent


@dataclass(frozen=True)
class RiskPrediction:
    score: float
    attack_probability: float
    sequence_surprise: float
    entity_pressure: float
    confidence: float
    reasons: list[str] = field(default_factory=list)
    predicted_next_stage: str = "credential validation and lateral movement"


class PredictiveRiskAgent:
    """
    Learns behavioural attack patterns from telemetry and scores new events using
    supervised probability, rare transition modelling, and short-window entity
    pressure. It is intentionally feature-based rather than signature/database
    matching, so novel combinations can raise risk before exact indicators exist.
    """

    def __init__(self, threshold: float = 0.58) -> None:
        self.threshold = threshold
        self.scaler = StandardScaler()
        self.model = HistGradientBoostingClassifier(max_iter=160, learning_rate=0.055, max_leaf_nodes=18, random_state=20260720)
        self._fit = False
        self._transition_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        self._event_counts: Counter[str] = Counter()
        self._normal_total = 0

    def _code(self, value: str, modulo: int) -> float:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return float(int(digest[:8], 16) % modulo) / max(1, modulo)

    def _timestamp(self, event: TelemetryEvent) -> datetime:
        return event.timestamp if isinstance(event.timestamp, datetime) else datetime.fromisoformat(str(event.timestamp))

    def _base_features(self, event: TelemetryEvent) -> list[float]:
        ts = self._timestamp(event)
        hour = ts.hour + ts.minute / 60
        metadata = event.metadata or {}
        source = str(metadata.get("source") or "")
        signal_conf = float(metadata.get("confidence") or 0)
        status_code = float(metadata.get("status_code") or 200)
        return [
            math.sin(2 * math.pi * hour / 24),
            math.cos(2 * math.pi * hour / 24),
            1.0 if event.success else 0.0,
            math.log1p(max(0.0, event.latency_ms)),
            math.log1p(max(0.0, event.bytes_out)),
            self._code(str(event.role), 17),
            self._code(event.event_type, 43),
            self._code(event.segment, 29),
            self._code(event.user_id, 53),
            self._code(event.device_id, 53),
            self._code(event.ip.rsplit(".", 1)[0], 53),
            1.0 if source == "live_traffic" else 0.0,
            min(1.0, signal_conf),
            1.0 if status_code >= 400 else 0.0,
        ]

    def fit(self, events: list[TelemetryEvent]) -> None:
        if not events:
            return
        normal = [event for event in events if event.label == "normal"]
        ordered = sorted(normal, key=lambda event: self._timestamp(event))
        last_by_entity: dict[str, str] = {}
        for event in ordered:
            key = f"{event.user_id}:{event.device_id}:{event.segment}"
            previous = last_by_entity.get(key)
            if previous:
                self._transition_counts[(event.segment, previous)][event.event_type] += 1
            last_by_entity[key] = event.event_type
            self._event_counts[event.event_type] += 1
            self._normal_total += 1

        matrix = np.array([self._base_features(event) for event in events])
        labels = np.array([0 if event.label == "normal" else 1 for event in events])
        if len(set(labels.tolist())) < 2:
            return
        self.scaler.fit(matrix)
        self.model.fit(self.scaler.transform(matrix), labels)
        self._fit = True

    def _sequence_surprise(self, event: TelemetryEvent, history: list[TelemetryEvent]) -> tuple[float, str | None]:
        entity_history = [
            item
            for item in reversed(history[-250:])
            if item.user_id == event.user_id or item.device_id == event.device_id or item.ip == event.ip
        ]
        previous = entity_history[0].event_type if entity_history else None
        if not previous:
            rarity = 1.0 - (self._event_counts[event.event_type] / max(1, self._normal_total))
            return min(1.0, max(0.0, rarity)), "Rare event type for baseline" if rarity > 0.75 else None
        bucket = self._transition_counts.get((event.segment, previous), Counter())
        total = sum(bucket.values())
        probability = (bucket[event.event_type] + 1) / (total + max(3, len(self._event_counts)))
        surprise = min(1.0, -math.log(probability) / 6.0)
        reason = f"Rare transition {previous}->{event.event_type}" if surprise >= 0.55 else None
        return surprise, reason

    def _entity_pressure(self, event: TelemetryEvent, history: list[TelemetryEvent]) -> tuple[float, str | None]:
        related = [
            item
            for item in history[-80:]
            if item.ip == event.ip or item.user_id == event.user_id or item.device_id == event.device_id
        ]
        if not related:
            return 0.0, None
        failures = sum(1 for item in related if not item.success)
        distinct_events = len({item.event_type for item in related})
        distinct_segments = len({item.segment for item in related})
        pressure = min(1.0, failures / 8 + distinct_events / 18 + distinct_segments / 12)
        reason = "Short-window entity pressure from failures or broad activity" if pressure >= 0.45 else None
        return pressure, reason

    def predict(self, event: TelemetryEvent, history: list[TelemetryEvent]) -> RiskPrediction:
        if not self._fit:
            raise RuntimeError("PredictiveRiskAgent must be fit before scoring")
        features = self.scaler.transform(np.array([self._base_features(event)]))
        probability = float(self.model.predict_proba(features)[0][1])
        sequence_surprise, sequence_reason = self._sequence_surprise(event, history)
        entity_pressure, entity_reason = self._entity_pressure(event, history)
        perimeter_confidence = float((event.metadata or {}).get("confidence") or 0)
        score = min(
            1.0,
            0.48 * probability
            + 0.22 * sequence_surprise
            + 0.18 * entity_pressure
            + 0.12 * min(1.0, perimeter_confidence),
        )
        reasons = [f"ML attack probability {probability:.2f}", f"Sequence surprise {sequence_surprise:.2f}"]
        if sequence_reason:
            reasons.append(sequence_reason)
        if entity_reason:
            reasons.append(entity_reason)
        if perimeter_confidence:
            reasons.append(f"Perimeter confidence {perimeter_confidence:.2f}")

        predicted_next_stage = "credential validation and lateral movement"
        if event.event_type in {"sqli_attempt", "path_traversal_attempt", "command_injection_attempt"}:
            predicted_next_stage = "web foothold expansion and data discovery"
        elif event.event_type in {"brute_force_attempt", "login"} and not event.success:
            predicted_next_stage = "valid-account abuse against privileged roles"
        elif "scan" in event.event_type or sequence_surprise > 0.7:
            predicted_next_stage = "service discovery followed by exploit selection"

        return RiskPrediction(
            score=round(score, 3),
            attack_probability=round(probability, 3),
            sequence_surprise=round(sequence_surprise, 3),
            entity_pressure=round(entity_pressure, 3),
            confidence=round(max(probability, score), 3),
            reasons=reasons,
            predicted_next_stage=predicted_next_stage,
        )
