from __future__ import annotations

from collections import defaultdict

from app.models.schemas import TelemetryEvent


class BaselineAgent:
    def build(self, events: list[TelemetryEvent]) -> dict:
        normals = [e for e in events if e.label == "normal"]
        by_segment: dict[str, list[TelemetryEvent]] = defaultdict(list)
        for event in normals:
            by_segment[event.segment].append(event)
        segment_stats = {}
        for segment, rows in by_segment.items():
            latencies = [e.latency_ms for e in rows]
            bytes_out = [e.bytes_out for e in rows]
            segment_stats[segment] = {
                "count": len(rows),
                "avg_latency_ms": sum(latencies) / max(1, len(latencies)),
                "avg_bytes_out": sum(bytes_out) / max(1, len(bytes_out)),
                "success_rate": sum(1 for e in rows if e.success) / max(1, len(rows)),
            }
        return {"segments": segment_stats, "training_rows": len(normals)}

