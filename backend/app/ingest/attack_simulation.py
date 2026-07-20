from __future__ import annotations

import random
from datetime import datetime, timezone

from app.rag.mitre_loader import build_mitre_corpus

TACTIC_TO_EVENT = {
    "reconnaissance": ("cert_lookup", "certificate-service", 220, 12, True),
    "resource-development": ("cert_lookup", "certificate-service", 250, 16, True),
    "initial-access": ("login", "auth-db", 310, 10, False),
    "execution": ("session_start", "candidate-portal", 240, 32, True),
    "persistence": ("session_start", "auth-db", 280, 24, True),
    "privilege-escalation": ("session_start", "auth-db", 330, 30, True),
    "defense-evasion": ("session_start", "auth-db", 300, 18, True),
    "defense-impairment": ("session_start", "auth-db", 360, 18, True),
    "credential-access": ("login", "auth-db", 120, 8, False),
    "discovery": ("exam_page", "candidate-portal", 260, 80, True),
    "lateral-movement": ("session_start", "marking", 310, 46, True),
    "collection": ("answer_save", "candidate-portal", 270, 720, True),
    "command-and-control": ("session_start", "proctoring", 420, 140, True),
    "exfiltration": ("script_open", "marking", 360, 980, True),
    "impact": ("cert_lookup", "certificate-service", 920, 6, False),
}


def find_technique(technique_id: str) -> dict:
    for technique in [t.model_dump() for t in build_mitre_corpus()]:
        if technique["id"].lower() == technique_id.lower():
            return technique
    raise KeyError(technique_id)


def build_attack_event(technique: dict, idx: int, total: int) -> dict:
    tactic = technique.get("tactics", ["discovery"])[0] or "discovery"
    event_type, segment, latency, bytes_out, success = TACTIC_TO_EVENT.get(
        tactic,
        ("exam_page", "candidate-portal", 260, 64, True),
    )
    role = "examiner" if segment == "marking" else "invigilator" if segment == "proctoring" else "candidate"
    jitter = random.Random(f"{technique['id']}-{idx}")
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": f"SIM-{technique['id']}-{idx:03d}",
        "role": role,
        "device_id": f"ATTACK-SIM-{technique['id'].replace('.', '-')}",
        "segment": segment,
        "ip": f"198.51.100.{20 + (idx % 120)}",
        "event_type": event_type,
        "success": success if idx % 4 else not success,
        "latency_ms": latency + jitter.randint(-20, 45) + idx * 3,
        "bytes_out": max(1, bytes_out + jitter.randint(-8, 70) + idx * 5),
        "metadata": {
            "simulation": True,
            "safe": True,
            "technique_id": technique["id"],
            "technique_name": technique["name"],
            "tactic": tactic,
            "note": "Benign ATT&CK telemetry simulation; no exploit or malware behavior is performed.",
            "step": idx,
            "steps": total,
        },
    }

