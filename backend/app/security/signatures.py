from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True)
class SignatureMatch:
    family: str
    technique_id: str
    event_type: str
    confidence: float
    reason: str
    block_immediately: bool = False


SQLI_PATTERNS = [
    re.compile(r"(?i)(?:'|\")\s*or\s*(?:'|\")?1(?:'|\")?\s*=\s*(?:'|\")?1"),
    re.compile(r"(?i)\bor\s+1\s*=\s*1\b"),
    re.compile(r"(?i)\bunion\s+select\b"),
    re.compile(r"(?i)(?:--|;--|/\*)"),
]
COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?:;|\|\||\||&&)\s*(?:whoami|id|cat|curl|wget|powershell|cmd|sh|bash)\b", re.I),
    re.compile(r"\$\([^)]{1,120}\)"),
    re.compile(r"`[^`]{1,120}`"),
]
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f)"),
]
XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script\b"),
    re.compile(r"(?i)\bonerror\s*="),
    re.compile(r"(?i)javascript\s*:"),
]
SCANNER_UA_PATTERNS = [
    re.compile(r"(?i)\b(sqlmap|nikto|nmap|hydra|gobuster|dirbuster|wfuzz|ffuf|python-requests|burp suite)\b"),
]


def scan_request(payload: str, user_agent: str, header_bytes: int, body_bytes: int) -> list[SignatureMatch]:
    matches: list[SignatureMatch] = []
    payload = f"{payload} {urllib.parse.unquote_plus(payload)}"
    if any(pattern.search(payload) for pattern in SQLI_PATTERNS):
        matches.append(
            SignatureMatch(
                family="sql_injection",
                technique_id="T1190",
                event_type="sqli_attempt",
                confidence=0.96,
                reason="SQL injection marker in query/body",
                block_immediately=True,
            )
        )
    if any(pattern.search(payload) for pattern in COMMAND_INJECTION_PATTERNS):
        matches.append(
            SignatureMatch(
                family="command_injection",
                technique_id="T1059",
                event_type="command_injection_attempt",
                confidence=0.95,
                reason="Command injection metacharacter and command marker in query/body",
                block_immediately=True,
            )
        )
    if any(pattern.search(payload) for pattern in PATH_TRAVERSAL_PATTERNS):
        matches.append(
            SignatureMatch(
                family="path_traversal",
                technique_id="T1083",
                event_type="path_traversal_attempt",
                confidence=0.9,
                reason="Path traversal marker in route/query/body",
                block_immediately=True,
            )
        )
    if any(pattern.search(payload) for pattern in XSS_PATTERNS):
        matches.append(
            SignatureMatch(
                family="xss",
                technique_id="T1189",
                event_type="xss_attempt",
                confidence=0.88,
                reason="XSS marker in query/body",
                block_immediately=True,
            )
        )
    if any(pattern.search(user_agent) for pattern in SCANNER_UA_PATTERNS):
        matches.append(
            SignatureMatch(
                family="scanner_user_agent",
                technique_id="T1595",
                event_type="scanner_user_agent",
                confidence=0.45,
                reason="Known scanner/tool User-Agent; supporting signal only",
                block_immediately=False,
            )
        )
    if header_bytes > 16_384 or body_bytes > 262_144:
        matches.append(
            SignatureMatch(
                family="malformed_or_oversized",
                technique_id="T1499",
                event_type="oversized_request",
                confidence=0.78,
                reason=f"Oversized request header/body ({header_bytes} header bytes, {body_bytes} body bytes)",
                block_immediately=False,
            )
        )
    return matches
