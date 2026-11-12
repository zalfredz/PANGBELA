"""Brute force detection from auth log events (team answer Q3).

Brute force may raise no Suricata alert, so login events are ingested on their own:
each is stored in auth_events, and once a source IP reaches BRUTE_FORCE_MIN_FAILURES
failures inside BRUTE_FORCE_WINDOW_SECONDS a brute_force incident opens. Later events
from that IP within INCIDENT_GROUP_WINDOW_SECONDS join it, successes included.
"""

import json
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import Connection, text

from app.config import Settings
from app.evidence import auth_log
from app.evidence.jsonl import LineError, Record
from app.evidence.store import EvidenceEvent, insert_evidence
from app.graph.rules import max_failures_in_window


def parse_lines(lines: list[str]) -> tuple[list[Record], int]:
    """Valid records and the number of lines ignored."""
    records, ignored = [], 0
    for line in lines:
        try:
            records.append(auth_log.parse(line))
        except LineError:
            ignored += 1
    return records, ignored


def _store(conn: Connection, r: Record) -> bool:
    """Insert one event; False if the same line was already stored."""
    return (
        conn.execute(
            text(
                "INSERT INTO auth_events (event_time, src_ip, result, raw, fields)"
                " VALUES (:ts, CAST(:src AS inet), :result, :raw, CAST(:fields AS jsonb))"
                " ON CONFLICT (event_time, md5(raw)) DO NOTHING RETURNING id"
            ),
            {
                "ts": r.ts,
                "src": r.src_ip,
                "result": r.fields["result"],
                "raw": r.raw,
                "fields": json.dumps(r.fields),
            },
        ).scalar()
        is not None
    )


def _open_incident(
    conn: Connection, src_ip: str, lo: datetime, hi: datetime, cfg: Settings
) -> UUID | None:
    """An existing brute_force incident for src_ip near [lo, hi], extended to cover it,
    or a new one if the stored failures reach the threshold, or None."""
    group = timedelta(seconds=cfg.INCIDENT_GROUP_WINDOW_SECONDS)
    incident_id = conn.execute(
        text(
            "SELECT id FROM incidents WHERE src_ip = CAST(:src AS inet)"
            " AND attack_type = 'brute_force'"
            " AND last_seen BETWEEN :lo - :group AND :hi + :group"
            " ORDER BY last_seen DESC LIMIT 1"
        ),
        {"src": src_ip, "lo": lo, "hi": hi, "group": group},
    ).scalar()
    if incident_id is not None:
        conn.execute(
            text(
                "UPDATE incidents SET first_seen = LEAST(first_seen, :lo),"
                " last_seen = GREATEST(last_seen, :hi), updated_at = now() WHERE id = :id"
            ),
            {"id": incident_id, "lo": lo, "hi": hi},
        )
        return incident_id

    window = timedelta(seconds=cfg.BRUTE_FORCE_WINDOW_SECONDS)
    failure_times = list(
        conn.execute(
            text(
                "SELECT event_time FROM auth_events WHERE src_ip = CAST(:src AS inet)"
                " AND result = 'failure' AND event_time BETWEEN :lo AND :hi"
            ),
            {"src": src_ip, "lo": lo - window, "hi": hi + window},
        ).scalars()
    )
    count, first = max_failures_in_window(failure_times, window)
    if count < cfg.BRUTE_FORCE_MIN_FAILURES:
        return None
    return conn.execute(
        text(
            "INSERT INTO incidents (src_ip, dest_ip, first_seen, last_seen, attack_type,"
            " opened_by) VALUES (CAST(:src AS inet), NULL, :first, :last, 'brute_force',"
            " 'auth_log') RETURNING id"
        ),
        {"src": src_ip, "first": min(first, lo), "last": max(hi, max(failure_times))},
    ).scalar_one()


def _attach(conn: Connection, incident_id: UUID) -> list[tuple[EvidenceEvent, datetime]]:
    """Store the incident's stored login events in its time range as evidence."""
    rows = conn.execute(
        text(
            "SELECT e.raw FROM auth_events e JOIN incidents i ON i.id = :id"
            " WHERE e.src_ip = i.src_ip AND e.event_time BETWEEN i.first_seen AND i.last_seen"
            " ORDER BY e.event_time"
        ),
        {"id": incident_id},
    ).scalars()
    events = [auth_log.parse(raw).to_evidence("auth_log", incident_id) for raw in rows]
    return insert_evidence(conn, events, collected_by="ingest")


def ingest_auth(
    conn: Connection, records: list[Record], cfg: Settings
) -> tuple[list[UUID], list[tuple[EvidenceEvent, datetime]]]:
    """Store the records and open or extend incidents. Returns the incidents touched
    and the newly stored evidence, for evidence_added."""
    stored = [r for r in sorted(records, key=lambda r: r.ts) if _store(conn, r)]
    incident_ids: list[UUID] = []
    added: list[tuple[EvidenceEvent, datetime]] = []
    for src_ip in dict.fromkeys(r.src_ip for r in stored):
        # Serialize per source IP, so two concurrent batches can't both open an incident.
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"auth|{src_ip}"}
        )
        times = [r.ts for r in stored if r.src_ip == src_ip]
        incident_id = _open_incident(conn, src_ip, min(times), max(times), cfg)
        if incident_id is None:
            continue
        incident_ids.append(incident_id)
        added += _attach(conn, incident_id)
    return incident_ids, added
