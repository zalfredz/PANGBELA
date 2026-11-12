"""Evidence events (spec section 6): every log line is normalized and stored here
before any agent sees it, so agents can only cite ids that exist in the database."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import Connection, text

EvidenceSource = Literal["suricata", "access_log", "auth_log", "process"]


def new_evidence_id() -> str:
    # 12 hex chars rather than 8: at 8 a few thousand events already carry a
    # percent-level collision chance on the primary key.
    return "ev_" + uuid.uuid4().hex[:12]


class EvidenceEvent(BaseModel):
    id: str = Field(default_factory=new_evidence_id)
    incident_id: UUID
    source: EvidenceSource
    ts: datetime  # UTC
    src_ip: str | None
    summary: str  # written by our code, never by the LLM
    raw: str  # the original line, unchanged
    fields: dict[str, Any]


def insert_evidence(
    conn: Connection, events: list[EvidenceEvent], collected_by: str
) -> list[tuple[EvidenceEvent, datetime]]:
    """Store events, skipping lines already stored for the incident.

    Returns the newly stored events with their created_at, for evidence_added.
    """
    added = []
    for ev in events:
        existing = conn.execute(
            text(
                "SELECT 1 FROM evidence"
                " WHERE incident_id = :incident_id AND source = :source AND ts = :ts AND raw = :raw"
            ),
            {"incident_id": ev.incident_id, "source": ev.source, "ts": ev.ts, "raw": ev.raw},
        ).scalar()
        if existing:
            continue
        # The app's clock, not the database's now(): the stream orders evidence
        # against agent_runs times, which the app also writes, and the two clocks
        # can disagree by more than a fast agent step takes.
        created_at = datetime.now(UTC)
        conn.execute(
            text(
                "INSERT INTO evidence"
                " (id, incident_id, source, ts, src_ip, summary, raw, fields, collected_by,"
                " created_at)"
                " VALUES (:id, :incident_id, :source, :ts, :src_ip, :summary, :raw,"
                " CAST(:fields AS jsonb), :collected_by, :created_at)"
            ),
            {
                "id": ev.id,
                "incident_id": ev.incident_id,
                "source": ev.source,
                "ts": ev.ts,
                "src_ip": ev.src_ip,
                "summary": ev.summary,
                "raw": ev.raw,
                "fields": json.dumps(ev.fields),
                "collected_by": collected_by,
                "created_at": created_at,
            },
        )
        added.append((ev, created_at))
    return added


def load_evidence(conn: Connection, incident_id: UUID) -> list[EvidenceEvent]:
    rows = conn.execute(
        text(
            "SELECT id, incident_id, source, ts, host(src_ip) AS src_ip, summary, raw, fields"
            " FROM evidence WHERE incident_id = :id ORDER BY ts, id"
        ),
        {"id": incident_id},
    ).mappings()
    return [EvidenceEvent(**row) for row in rows]
