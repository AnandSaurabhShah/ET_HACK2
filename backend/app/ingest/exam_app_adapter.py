from __future__ import annotations

from datetime import timezone

from app.models.schemas import RawEvent, TelemetryEvent
from app.storage import utc_now


def normalize_frontend_event(raw: RawEvent) -> TelemetryEvent:
    """Convert real frontend auth/cert events into the common telemetry shape."""
    ts = raw.timestamp or utc_now()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return TelemetryEvent(
        event_id=raw.event_id or f"REAL-{int(ts.timestamp() * 1000)}",
        timestamp=ts,
        user_id=raw.user_id,
        role=raw.role,
        device_id=raw.device_id,
        segment=raw.segment,
        ip=raw.ip,
        event_type=raw.event_type,
        success=raw.success,
        latency_ms=raw.latency_ms,
        bytes_out=raw.bytes_out,
        label="real_frontend_event",
        metadata={**raw.metadata, "source": "frontend exam app adapter"},
    )

