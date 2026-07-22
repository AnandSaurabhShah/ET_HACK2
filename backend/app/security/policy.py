from __future__ import annotations

import ipaddress
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field


REDIRECT_PARAM_KEYS = {"next", "redirect", "redirect_uri", "return", "return_to", "url", "continue"}
UNSAFE_SCHEMES = {"javascript", "data", "vbscript", "file"}


def split_csv(value: str) -> set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def is_trusted_proxy(peer_ip: str, trusted_entries: set[str]) -> bool:
    if peer_ip.lower() in trusted_entries:
        return True
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for entry in trusted_entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if peer in network:
            return True
    return False


def extract_forwarded_ip(header_value: str) -> str | None:
    first = header_value.split(",", 1)[0].strip()
    if not first:
        return None
    candidate = first.strip("\"[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def unsafe_redirect_target(value: str, allowed_hosts: set[str]) -> str | None:
    target = urllib.parse.unquote(value).strip()
    if not target:
        return None
    lowered = target.lower()
    if lowered.startswith("//"):
        return "protocol-relative redirect target"
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme.lower() in UNSAFE_SCHEMES:
        return f"unsafe redirect scheme {parsed.scheme}"
    if parsed.scheme or parsed.netloc:
        host = (parsed.hostname or "").lower()
        if host not in allowed_hosts:
            return f"external redirect host {host or parsed.netloc}"
    if "\r" in target or "\n" in target:
        return "redirect target contains control characters"
    return None


def validate_password_strength(password: str, *, user_id: str, name: str = "", email: str = "", phone: str = "") -> dict:
    failures: list[str] = []
    if len(password) < 12:
        failures.append("Use at least 12 characters.")
    if not re.search(r"[a-z]", password):
        failures.append("Add a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        failures.append("Add an uppercase letter.")
    if not re.search(r"\d", password):
        failures.append("Add a number.")
    if not re.search(r"[^A-Za-z0-9]", password):
        failures.append("Add a symbol.")

    lowered = password.lower()
    sensitive_terms = {user_id.lower(), email.split("@", 1)[0].lower(), phone[-4:].lower()}
    sensitive_terms.update(part.lower() for part in re.split(r"[^A-Za-z0-9]+", name) if len(part) >= 3)
    sensitive_terms = {term for term in sensitive_terms if len(term) >= 3}
    reused = sorted(term for term in sensitive_terms if term and term in lowered)
    if reused:
        failures.append("Do not include your roll number, name, email, phone, or other sensitive personal details.")

    common = {"password", "candidate", "cbse", "exam", "pariksha", "qwerty", "admin", "security", "welcome"}
    if any(term in lowered for term in common):
        failures.append("Avoid common words used in exam portals or demo accounts.")

    return {"ok": not failures, "reasons": failures}


@dataclass
class MfaChallenge:
    user_id: str
    role: str
    code: str
    expires_at: float
    attempts: int = 0


@dataclass
class MfaStore:
    ttl_seconds: int = 300
    max_attempts: int = 5
    _items: dict[str, MfaChallenge] = field(default_factory=dict)

    def start(self, *, user_id: str, role: str) -> dict:
        self._prune()
        challenge_id = "MFA-" + secrets.token_urlsafe(12)
        code = f"{secrets.randbelow(1_000_000):06d}"
        challenge = MfaChallenge(user_id=user_id, role=role, code=code, expires_at=time.time() + self.ttl_seconds)
        self._items[challenge_id] = challenge
        return {
            "challenge_id": challenge_id,
            "expires_at": challenge.expires_at,
            "delivery": "demo",
            "demo_code": code,
        }

    def verify(self, *, challenge_id: str, code: str, user_id: str, role: str) -> dict:
        self._prune()
        challenge = self._items.get(challenge_id)
        if not challenge:
            return {"ok": False, "reason": "MFA challenge expired or not found."}
        challenge.attempts += 1
        if challenge.attempts > self.max_attempts:
            self._items.pop(challenge_id, None)
            return {"ok": False, "reason": "Too many MFA attempts."}
        if challenge.user_id.lower() != user_id.lower() or challenge.role != role:
            return {"ok": False, "reason": "MFA challenge does not match this account."}
        if not secrets.compare_digest(challenge.code, code.strip()):
            return {"ok": False, "reason": "Invalid MFA code."}
        self._items.pop(challenge_id, None)
        return {"ok": True}

    def _prune(self) -> None:
        now = time.time()
        expired = [key for key, challenge in self._items.items() if challenge.expires_at <= now]
        for key in expired:
            self._items.pop(key, None)
