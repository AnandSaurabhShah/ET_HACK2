from __future__ import annotations

import hashlib
import math
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.models.schemas import TelemetryEvent


class AnomalyAgent:
    def __init__(self, threshold: float = 0.52) -> None:
        self.threshold = threshold
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=160, contamination=0.11, random_state=20260720)
        self._fit = False
        self._mean: np.ndarray | None = None
        self._std: np.ndarray | None = None

    def _code(self, value: str, modulo: int) -> float:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return int(digest[:8], 16) % modulo

    def features(self, event: TelemetryEvent) -> list[float]:
        ts = event.timestamp if isinstance(event.timestamp, datetime) else datetime.fromisoformat(str(event.timestamp))
        hour = ts.hour + ts.minute / 60
        return [
            math.sin(2 * math.pi * hour / 24),
            math.cos(2 * math.pi * hour / 24),
            1.0 if event.success else 0.0,
            math.log1p(max(0.0, event.latency_ms)),
            math.log1p(max(0.0, event.bytes_out)),
            self._code(str(event.role), 7),
            self._code(event.event_type, 17),
            self._code(event.segment, 13),
            self._code(event.ip.rsplit(".", 1)[0], 31),
        ]

    def fit(self, events: list[TelemetryEvent]) -> None:
        normal = [e for e in events if e.label == "normal"]
        matrix = np.array([self.features(e) for e in normal])
        self._mean = matrix.mean(axis=0)
        self._std = np.maximum(matrix.std(axis=0), 0.05)
        self.scaler.fit(matrix)
        self.model.fit(self.scaler.transform(matrix))
        self._fit = True

    def score(self, event: TelemetryEvent) -> float:
        if not self._fit:
            raise RuntimeError("AnomalyAgent must be fit before scoring")
        x = self.scaler.transform(np.array([self.features(event)]))
        raw = -float(self.model.decision_function(x)[0])
        isolation_score = 1 / (1 + math.exp(-8 * (raw + 0.02)))
        vector = np.array(self.features(event))
        zmax = float(np.max(np.abs((vector - self._mean) / self._std))) if self._mean is not None and self._std is not None else 0
        z_score = 1 / (1 + math.exp(-1.15 * (zmax - 2.4)))
        return max(0.0, min(1.0, 0.58 * isolation_score + 0.42 * z_score))

    def is_anomaly(self, event: TelemetryEvent) -> bool:
        return self.score(event) >= self.threshold
