from __future__ import annotations

import hashlib
import json
from threading import Lock
from typing import Any

from app.models.schemas import AuditEntry
from app.paths import AUDIT_LOG_PATH, ensure_dirs
from app.storage import append_jsonl, read_jsonl, utc_now
from app.db import insert_audit

_AUDIT_LOCK = Lock()


def _hash_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AuditLog:
    def __init__(self) -> None:
        ensure_dirs()

    def entries(self, limit: int = 100) -> list[AuditEntry]:
        rows = read_jsonl(AUDIT_LOG_PATH)
        return [AuditEntry(**row) for row in rows[-limit:]][::-1]

    def verify(self) -> dict:
        rows = read_jsonl(AUDIT_LOG_PATH)
        previous_hash = "GENESIS"
        for position, row in enumerate(rows):
            claimed_hash = row.get("hash")
            payload = {k: v for k, v in row.items() if k != "hash"}
            if row.get("index") != position:
                return {"ok": False, "reason": "index_mismatch", "position": position}
            if row.get("previous_hash") != previous_hash:
                return {"ok": False, "reason": "previous_hash_mismatch", "position": position}
            if _hash_payload(payload) != claimed_hash:
                return {"ok": False, "reason": "hash_mismatch", "position": position}
            previous_hash = claimed_hash
        return {"ok": True, "entries": len(rows), "head": previous_hash}

    def append(
        self,
        *,
        actor: str,
        action: str,
        justification: str,
        blast_radius: int,
        payload: dict[str, Any] | None = None,
    ) -> AuditEntry:
        with _AUDIT_LOCK:
            rows = read_jsonl(AUDIT_LOG_PATH)
            previous_hash = rows[-1]["hash"] if rows else "GENESIS"
            entry_payload = {
                "index": len(rows),
                "timestamp": utc_now().isoformat(),
                "actor": actor,
                "action": action,
                "justification": justification,
                "blast_radius": blast_radius,
                "payload": payload or {},
                "previous_hash": previous_hash,
            }
            entry_payload["hash"] = _hash_payload(entry_payload)
            append_jsonl(AUDIT_LOG_PATH, entry_payload)
            insert_audit(entry_payload)
            return AuditEntry(**entry_payload)
