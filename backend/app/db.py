from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import get_settings
from app.paths import ensure_dirs
from app.storage import utc_now


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "telemetry_events"

    event_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    label: Mapped[str] = mapped_column(String(80), index=True)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    inserted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AlertRecord(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    inserted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditRecord(Base):
    __tablename__ = "audit_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_index: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    actor: Mapped[str] = mapped_column(String(120), index=True)
    action: Mapped[str] = mapped_column(String(200), index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    entry_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    previous_hash: Mapped[str] = mapped_column(String(128), index=True)
    inserted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


engine = create_engine(get_settings().database_url, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db() -> None:
    ensure_dirs()
    Base.metadata.create_all(bind=engine)


def _dump(payload: dict[str, Any]) -> str:
    return json.dumps(payload, default=str, sort_keys=True)


def upsert_event(payload: dict[str, Any]) -> None:
    with SessionLocal() as session:
        record = session.get(EventRecord, payload["event_id"])
        if not record:
            record = EventRecord(
                event_id=payload["event_id"],
                timestamp=datetime.fromisoformat(str(payload["timestamp"]).replace("Z", "+00:00")),
                label=payload.get("label", "unknown"),
                technique_id=payload.get("technique_id"),
                payload_json=_dump(payload),
            )
            session.add(record)
        else:
            record.payload_json = _dump(payload)
            record.label = payload.get("label", record.label)
            record.technique_id = payload.get("technique_id")
        session.commit()


def upsert_alert(payload: dict[str, Any]) -> None:
    technique_id = None
    techniques = payload.get("attribution", {}).get("techniques", [])
    if techniques:
        technique_id = techniques[0].get("id")
    with SessionLocal() as session:
        record = session.get(AlertRecord, payload["alert_id"])
        if not record:
            record = AlertRecord(
                alert_id=payload["alert_id"],
                severity=payload.get("severity", "low"),
                technique_id=technique_id,
                status=payload.get("status", "open"),
                payload_json=_dump(payload),
            )
            session.add(record)
        else:
            record.severity = payload.get("severity", record.severity)
            record.technique_id = technique_id
            record.status = payload.get("status", record.status)
            record.payload_json = _dump(payload)
        session.commit()


def insert_audit(payload: dict[str, Any]) -> None:
    with SessionLocal() as session:
        exists = session.execute(select(AuditRecord).where(AuditRecord.entry_hash == payload["hash"])).scalar_one_or_none()
        if exists:
            return
        session.add(
            AuditRecord(
                audit_index=payload["index"],
                actor=payload["actor"],
                action=payload["action"],
                payload_json=_dump(payload),
                entry_hash=payload["hash"],
                previous_hash=payload["previous_hash"],
            )
        )
        session.commit()


def sync_events(events: list[dict[str, Any]]) -> None:
    for event in events:
        upsert_event(event)


def sync_alerts(alerts: list[dict[str, Any]]) -> None:
    for alert in alerts:
        upsert_alert(alert)


def db_health() -> dict[str, Any]:
    with SessionLocal() as session:
        session.execute(text("SELECT 1"))
        event_count = session.query(EventRecord).count()
        alert_count = session.query(AlertRecord).count()
        audit_count = session.query(AuditRecord).count()
    return {"ok": True, "events": event_count, "alerts": alert_count, "audit_entries": audit_count}
