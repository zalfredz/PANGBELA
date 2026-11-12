"""Alert to incident grouping (spec section 9).

An alert joins an incident with the same src_ip and dest_ip whose last_seen is
within INCIDENT_GROUP_WINDOW_SECONDS of the alert; otherwise it opens a new one.
Each alert is also stored as a suricata evidence event.
"""

import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import Connection, text

from app.evidence.store import EvidenceEvent, insert_evidence
from app.ingest.eve_parser import Alert

# Context fields kept on the suricata evidence event for the rules and agents.
_FIELD_KEYS = (
    "signature_id",
    "signature",
    "category",
    "flow_id",
    "src_port",
    "dest_port",
    "proto",
    "severity",
    "http_hostname",
    "http_url",
    "http_method",
    "http_user_agent",
    "http_status",
)


def _summary(a: Alert) -> str:
    # Only rule metadata and addresses: URL and user agent are attacker-controlled
    # and stay in raw/fields, where agents see them inside the untrusted block.
    src = f"{a.src_ip}:{a.src_port}" if a.src_port is not None else a.src_ip
    dst = f"{a.dest_ip}:{a.dest_port}" if a.dest_port is not None else a.dest_ip
    return f"Suricata alert {a.signature_id} [{a.category}] {a.signature} {src} -> {dst}"


def _find_or_create_incident(conn: Connection, a: Alert, window: timedelta) -> UUID:
    # Serialize grouping per IP pair so two concurrent ingest requests cannot both
    # decide "no incident yet" and open duplicates. Released at transaction end.
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"{a.src_ip}|{a.dest_ip}"},
    )
    incident_id = conn.execute(
        text(
            "SELECT id FROM incidents"
            " WHERE src_ip = CAST(:src AS inet) AND dest_ip = CAST(:dst AS inet)"
            " AND last_seen BETWEEN :ts - :window AND :ts + :window"
            " ORDER BY last_seen DESC LIMIT 1"
        ),
        {"src": a.src_ip, "dst": a.dest_ip, "ts": a.ts, "window": window},
    ).scalar()
    if incident_id is not None:
        conn.execute(
            text(
                "UPDATE incidents SET first_seen = LEAST(first_seen, :ts),"
                " last_seen = GREATEST(last_seen, :ts), updated_at = now() WHERE id = :id"
            ),
            {"id": incident_id, "ts": a.ts},
        )
        return incident_id
    return conn.execute(
        text(
            "INSERT INTO incidents (src_ip, dest_ip, first_seen, last_seen)"
            " VALUES (CAST(:src AS inet), CAST(:dst AS inet), :ts, :ts) RETURNING id"
        ),
        {"src": a.src_ip, "dst": a.dest_ip, "ts": a.ts},
    ).scalar_one()


def group_alert(
    conn: Connection,
    a: Alert,
    window_seconds: int,
    signature_types: Mapping[int, str] | None = None,
) -> tuple[UUID, list[tuple[EvidenceEvent, datetime]]]:
    """Attach one alert to an incident and store it and its evidence event.

    signature_types maps the lab's own signature ids to an attack type
    (RCE_SIGNATURE_IDS, BRUTE_FORCE_SIGNATURE_IDS); a match sets the type of an
    incident that has none yet.

    Returns the incident id and the newly stored evidence, for evidence_added.
    """
    incident_id = _find_or_create_incident(conn, a, timedelta(seconds=window_seconds))
    attack_type = (signature_types or {}).get(a.signature_id)
    if attack_type is not None:
        conn.execute(
            text(
                "UPDATE incidents SET attack_type = :t, updated_at = now()"
                " WHERE id = :id AND attack_type = 'unknown'"
            ),
            {"t": attack_type, "id": incident_id},
        )
    conn.execute(
        text(
            "INSERT INTO alerts (incident_id, ts, src_ip, dest_ip, signature_id, signature,"
            " category, flow_id, raw_json)"
            " VALUES (:incident_id, :ts, CAST(:src AS inet), CAST(:dst AS inet), :sid, :sig,"
            " :cat, :flow, CAST(:raw AS jsonb))"
        ),
        {
            "incident_id": incident_id,
            "ts": a.ts,
            "src": a.src_ip,
            "dst": a.dest_ip,
            "sid": a.signature_id,
            "sig": a.signature,
            "cat": a.category,
            "flow": a.flow_id,
            "raw": json.dumps(a.raw),
        },
    )
    added = insert_evidence(
        conn,
        [
            EvidenceEvent(
                incident_id=incident_id,
                source="suricata",
                ts=a.ts,
                src_ip=a.src_ip,
                summary=_summary(a),
                raw=json.dumps(a.raw, separators=(",", ":")),
                fields={k: getattr(a, k) for k in _FIELD_KEYS},
            )
        ],
        collected_by="ingest",
    )
    return incident_id, added
