from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MITRE_PATH = ROOT / "app" / "rag" / "fixtures" / "mitre_enterprise_techniques.json"

TACTIC_TO_EVENT = {
    "reconnaissance": ("cert_lookup", "certificate-service", 220, 12, True),
    "resource-development": ("cert_lookup", "certificate-service", 250, 16, True),
    "initial-access": ("login", "auth-db", 310, 10, False),
    "execution": ("session_start", "candidate-portal", 240, 32, True),
    "persistence": ("session_start", "auth-db", 280, 24, True),
    "privilege-escalation": ("session_start", "auth-db", 330, 30, True),
    "defense-evasion": ("session_start", "auth-db", 300, 18, True),
    "stealth": ("session_start", "auth-db", 300, 18, True),
    "defense-impairment": ("session_start", "auth-db", 360, 18, True),
    "credential-access": ("login", "auth-db", 120, 8, False),
    "discovery": ("exam_page", "candidate-portal", 260, 80, True),
    "lateral-movement": ("session_start", "marking", 310, 46, True),
    "collection": ("answer_save", "candidate-portal", 270, 720, True),
    "command-and-control": ("session_start", "proctoring", 420, 140, True),
    "exfiltration": ("script_open", "marking", 360, 980, True),
    "impact": ("cert_lookup", "certificate-service", 920, 6, False),
}


def load_techniques() -> list[dict]:
    if not MITRE_PATH.exists():
        raise SystemExit(f"Missing {MITRE_PATH}. Run: cd backend && python seed.py")
    return json.loads(MITRE_PATH.read_text(encoding="utf-8"))


def find_technique(techniques: list[dict], technique_id: str) -> dict:
    for technique in techniques:
        if technique["id"].lower() == technique_id.lower():
            return technique
    raise SystemExit(f"Technique {technique_id} not found in local ATT&CK corpus.")


def post_event(api: str, event: dict) -> dict:
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        f"{api.rstrip('/')}/ingest/events",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach backend at {api}: {exc}") from exc


def build_event(technique: dict, idx: int, total: int) -> dict:
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
            "source": "backend/tools/attack_simulator.py",
            "technique_id": technique["id"],
            "technique_name": technique["name"],
            "tactic": tactic,
            "note": "Benign ATT&CK telemetry simulation; no exploit or malware behavior is performed.",
            "step": idx,
            "steps": total,
        },
    }


def list_techniques(techniques: list[dict], tactic: str | None = None, limit: int = 80) -> None:
    rows = techniques
    if tactic:
        rows = [t for t in rows if tactic in t.get("tactics", [])]
    for technique in rows[:limit]:
        tactics = ",".join(technique.get("tactics", []))
        print(f"{technique['id']:12} {technique['name'][:54]:54} {tactics}")
    if len(rows) > limit:
        print(f"... {len(rows) - limit} more. Use --limit or --tactic.")


def simulate(api: str, technique: dict, count: int, delay: float) -> None:
    print(f"Simulating {technique['id']} - {technique['name']}")
    print("SAFE MODE: sends labelled telemetry only; does not exploit the website.")
    for idx in range(1, count + 1):
        event = build_event(technique, idx, count)
        result = post_event(api, event)
        print(
            f"{idx:02d}/{count} score={result.get('score')} "
            f"alert={result.get('alert_id')} segment={event['segment']} event={event['event_type']}"
        )
        if delay:
            time.sleep(delay)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Safe MITRE ATT&CK telemetry simulator for Aegis-CNI.")
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="Aegis-CNI backend URL")
    parser.add_argument("--list", action="store_true", help="List local ATT&CK techniques")
    parser.add_argument("--tactic", help="Filter --list by tactic, e.g. credential-access")
    parser.add_argument("--limit", type=int, default=80, help="List limit")
    parser.add_argument("--technique", help="Technique ID to simulate, e.g. T1110")
    parser.add_argument("--count", type=int, default=8, help="Telemetry events to send")
    parser.add_argument("--delay", type=float, default=0.25, help="Delay between events")
    args = parser.parse_args(argv)

    techniques = load_techniques()
    if args.list:
        list_techniques(techniques, args.tactic, args.limit)
        return 0
    if not args.technique:
        parser.error("Provide --technique Txxxx or use --list")
    simulate(args.api, find_technique(techniques, args.technique), args.count, args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

