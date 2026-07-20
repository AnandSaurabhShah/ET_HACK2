from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import get_settings

_requests: dict[str, deque[float]] = defaultdict(deque)


def require_operator_api_key(x_aegis_api_key: Annotated[str | None, Header()] = None) -> None:
    settings = get_settings()
    if not settings.api_key:
        return
    if x_aegis_api_key != settings.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Aegis API key")


def check_ingest_rate_limit(request: Request) -> None:
    # Request-rate accounting is centralized in the always-on middleware so
    # /ingest/events is not double-counted.
    return


OperatorAuth = Depends(require_operator_api_key)


@dataclass
class RateSignal:
    event_type: str
    technique_id: str
    confidence: float
    reason: str
    count: int


@dataclass
class RateTracker:
    window_seconds: int = 60
    request_threshold: int = 90
    endpoint_threshold: int = 24
    failed_login_ip_threshold: int = 8
    failed_login_user_threshold: int = 5
    _request_times: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    _endpoints: dict[str, deque[tuple[float, str]]] = field(default_factory=lambda: defaultdict(deque))
    _failed_login_ip: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    _failed_login_user: dict[tuple[str, str], deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def _prune(self, bucket: deque, now: float) -> None:
        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()

    def _prune_endpoints(self, bucket: deque[tuple[float, str]], now: float) -> None:
        while bucket and now - bucket[0][0] > self.window_seconds:
            bucket.popleft()

    def record_request(self, ip: str, path: str, failed_login: bool, target_user_id: str | None = None) -> dict:
        now = time.time()
        req_bucket = self._request_times[ip]
        req_bucket.append(now)
        self._prune(req_bucket, now)

        endpoint_bucket = self._endpoints[ip]
        endpoint_bucket.append((now, path))
        self._prune_endpoints(endpoint_bucket, now)
        distinct_endpoints = len({item_path for _, item_path in endpoint_bucket})

        signals: list[RateSignal] = []
        if len(req_bucket) >= self.request_threshold:
            signals.append(
                RateSignal(
                    event_type="request_burst",
                    technique_id="T1595",
                    confidence=0.82,
                    reason=f"{len(req_bucket)} requests in {self.window_seconds}s",
                    count=len(req_bucket),
                )
            )
        if distinct_endpoints >= self.endpoint_threshold:
            signals.append(
                RateSignal(
                    event_type="scan_burst",
                    technique_id="T1595",
                    confidence=0.86,
                    reason=f"{distinct_endpoints} distinct endpoints in {self.window_seconds}s",
                    count=distinct_endpoints,
                )
            )

        if failed_login:
            ip_bucket = self._failed_login_ip[ip]
            ip_bucket.append(now)
            self._prune(ip_bucket, now)
            if len(ip_bucket) >= self.failed_login_ip_threshold:
                signals.append(
                    RateSignal(
                        event_type="brute_force_attempt",
                        technique_id="T1110",
                        confidence=0.9,
                        reason=f"{len(ip_bucket)} failed login attempts from IP in {self.window_seconds}s",
                        count=len(ip_bucket),
                    )
                )
            if target_user_id:
                user_key = (ip, target_user_id.lower())
                user_bucket = self._failed_login_user[user_key]
                user_bucket.append(now)
                self._prune(user_bucket, now)
                if len(user_bucket) >= self.failed_login_user_threshold:
                    signals.append(
                        RateSignal(
                            event_type="brute_force_attempt",
                            technique_id="T1110",
                            confidence=0.92,
                            reason=f"{len(user_bucket)} failed login attempts against {target_user_id}",
                            count=len(user_bucket),
                        )
                    )

        return {"signals": signals, "ingest_allowed": len(req_bucket) <= get_settings().ingest_rate_limit_per_minute}


class IpBlocklist:
    def __init__(self, cooldown_seconds: int = 900) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._blocked: dict[str, dict] = {}

    def is_blocked(self, ip: str) -> bool:
        entry = self._blocked.get(ip)
        if not entry:
            return False
        if time.time() >= entry["expires_at"]:
            self._blocked.pop(ip, None)
            return False
        return True

    def block(self, ip: str, *, technique_id: str, reason: str, confidence: float) -> dict:
        entry = {
            "ip": ip,
            "technique_id": technique_id,
            "reason": reason,
            "confidence": confidence,
            "blocked_at": time.time(),
            "expires_at": time.time() + self.cooldown_seconds,
        }
        self._blocked[ip] = entry
        return entry

    def snapshot(self) -> list[dict]:
        return [entry for ip, entry in list(self._blocked.items()) if self.is_blocked(ip)]


GLOBAL_RATE_TRACKER = RateTracker()
GLOBAL_BLOCKLIST = IpBlocklist(cooldown_seconds=get_settings().perimeter_block_cooldown_seconds)
