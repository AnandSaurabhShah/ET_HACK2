from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Role = Literal["candidate", "invigilator", "examiner", "security", "system"]
Severity = Literal["low", "medium", "high", "critical"]


class RawEvent(BaseModel):
    event_id: str | None = None
    timestamp: datetime | None = None
    user_id: str = "anonymous"
    role: Role | str = "candidate"
    device_id: str = "unknown-device"
    segment: str = "public"
    ip: str = "127.0.0.1"
    event_type: str
    success: bool = True
    latency_ms: float = 120
    bytes_out: float = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelemetryEvent(RawEvent):
    event_id: str
    timestamp: datetime
    label: str = "normal"
    attack_id: str | None = None
    technique_id: str | None = None


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    description: str = ""
    mitigations: list[str] = Field(default_factory=list)
    url: str = ""


class Attribution(BaseModel):
    alert_id: str
    techniques: list[MitreTechnique]
    confidence: float
    evidence: list[str]
    likely_next_stage: str
    recommendation: str


class Alert(BaseModel):
    alert_id: str
    event: TelemetryEvent
    anomaly_score: float
    severity: Severity
    title: str
    attribution: Attribution
    created_at: datetime
    status: Literal["open", "contained", "queued"] = "open"


class PlaybookStep(BaseModel):
    name: str
    action: str
    blast_radius: int
    executable: bool = True
    status: Literal["pending", "executed", "queued", "approved"] = "pending"
    verified: bool = False
    details: str | None = None


class PlaybookRun(BaseModel):
    run_id: str
    alert_id: str
    status: Literal["executed", "queued_for_approval", "approved"]
    steps: list[PlaybookStep]
    justification: str
    autonomous_percent: float


class AuditEntry(BaseModel):
    index: int
    timestamp: datetime
    actor: str
    action: str
    justification: str
    blast_radius: int
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    hash: str
