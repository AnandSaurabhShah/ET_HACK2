from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Iterable

from app.models.schemas import TelemetryEvent


ROLES = ["candidate", "invigilator", "examiner"]
EVENT_TYPES = ["login", "session_start", "exam_page", "cert_lookup", "answer_save", "script_open"]
SEGMENTS = ["candidate-portal", "proctoring", "marking", "certificate-service", "auth-db"]


def _event(
    idx: int,
    ts: datetime,
    user_id: str,
    role: str,
    device_id: str,
    segment: str,
    ip: str,
    event_type: str,
    success: bool,
    latency_ms: float,
    bytes_out: float,
    label: str = "normal",
    attack_id: str | None = None,
    technique_id: str | None = None,
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=f"EVT-{idx:05d}",
        timestamp=ts,
        user_id=user_id,
        role=role,
        device_id=device_id,
        segment=segment,
        ip=ip,
        event_type=event_type,
        success=success,
        latency_ms=round(latency_ms, 2),
        bytes_out=round(bytes_out, 2),
        label=label,
        attack_id=attack_id,
        technique_id=technique_id,
        metadata={"source": "SIMULATED synthetic telemetry fixture"},
    )


def generate_events(seed: int = 20260720) -> list[TelemetryEvent]:
    """Generate deterministic labelled exam-portal telemetry.

    SIMULATED/MOCKED: this dataset models exam infrastructure behaviour for a
    repeatable hackathon demo. It is not a real CBSE/CERT-In dataset.
    """
    rng = random.Random(seed)
    start = datetime(2026, 7, 20, 3, 30, tzinfo=timezone.utc)
    events: list[TelemetryEvent] = []
    idx = 1

    for minute in range(720):
        ts = start + timedelta(minutes=minute)
        for _ in range(rng.randint(0, 3)):
            role = rng.choice(ROLES)
            segment = {
                "candidate": "candidate-portal",
                "invigilator": "proctoring",
                "examiner": "marking",
            }[role]
            user = {
                "candidate": f"CAND-2026-{rng.randint(1, 9000):06d}",
                "invigilator": f"INV-DEL-{rng.randint(1, 350):04d}",
                "examiner": f"OSM-{rng.randint(1000, 9999)}",
            }[role]
            event_type = rng.choices(EVENT_TYPES, weights=[8, 6, 18, 3, 20, 7])[0]
            success = rng.random() > 0.025
            latency = rng.gauss(130, 30) + (40 if event_type == "cert_lookup" else 0)
            bytes_out = max(4, rng.gauss(45, 22))
            events.append(_event(idx, ts, user, role, f"DEV-{rng.randint(1, 220):03d}", segment, f"10.8.{rng.randint(1, 12)}.{rng.randint(4, 250)}", event_type, success, latency, bytes_out))
            idx += 1

    attacks = [
        ("APT-CBSE-26-A", "T1110", "credential_access", "login", "auth-db", False, 85, 8),
        ("APT-CBSE-26-A", "T1078", "defense_evasion", "session_start", "auth-db", True, 110, 18),
        ("APT-CBSE-26-B", "T1499", "impact", "cert_lookup", "certificate-service", False, 880, 6),
        ("APT-CBSE-26-C", "T1021", "lateral_movement", "session_start", "marking", True, 260, 40),
        ("APT-CBSE-26-C", "T1041", "exfiltration", "script_open", "marking", True, 300, 950),
        ("APT-CBSE-26-C", "T1005", "collection", "answer_save", "candidate-portal", True, 240, 700),
    ]
    for offset, (attack_id, technique_id, label, event_type, segment, success, latency, bytes_out) in enumerate(attacks):
        base = start + timedelta(minutes=180 + offset * 52)
        for step in range(18):
            ts = base + timedelta(minutes=step * rng.randint(1, 4))
            role = "candidate" if segment == "candidate-portal" else "examiner" if segment == "marking" else "candidate"
            events.append(
                _event(
                    idx,
                    ts,
                    f"ADV-{attack_id[-1]}-{step:03d}",
                    role,
                    f"DEV-X-{offset}",
                    segment,
                    f"203.0.113.{20 + offset}",
                    event_type,
                    success if step % 5 else not success,
                    latency + rng.gauss(0, 30),
                    bytes_out + rng.gauss(0, 20),
                    label=label,
                    attack_id=attack_id,
                    technique_id=technique_id,
                )
            )
            idx += 1

    return sorted(events, key=lambda e: e.timestamp)

