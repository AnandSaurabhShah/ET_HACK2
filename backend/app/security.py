from __future__ import annotations

import time
from collections import defaultdict, deque
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
    limit = get_settings().ingest_rate_limit_per_minute
    if limit <= 0:
        return
    client = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = _requests[client]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Ingest rate limit exceeded")
    bucket.append(now)


OperatorAuth = Depends(require_operator_api_key)

