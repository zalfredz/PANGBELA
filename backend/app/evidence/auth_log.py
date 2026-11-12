"""Authentication log evidence tool: query by source IP and time range.

JSON Lines with the fields from docs/log-schema.md: timestamp, event_type, username,
src_ip, result ("success" or "failure"), service, request_id (optional), authorized
(optional boolean; false marks a login the lab defines as unauthorized).
"""

from datetime import datetime
from uuid import UUID

from app.evidence import jsonl
from app.evidence.store import EvidenceEvent

SOURCE = "auth_log"
RESULTS = ("success", "failure")
available = jsonl.available


def parse(line: str) -> jsonl.Record:
    obj = jsonl.load(line)
    ts = jsonl.timestamp(obj)
    src_ip = jsonl.ip(obj, "src_ip")
    result = jsonl.text(obj, "result", required=True)
    if result not in RESULTS:
        raise jsonl.LineError("result is not success or failure")
    username = jsonl.text(obj, "username")
    service = jsonl.text(obj, "service")
    # Written by the lab's auth service from its ground truth: false marks a login the
    # lab defines as unauthorized. Anything but a JSON boolean counts as not stated.
    authorized = obj.get("authorized")
    if not isinstance(authorized, bool):
        authorized = None
    return jsonl.Record(
        ts=ts,
        src_ip=src_ip,
        # The username is attacker-chosen in a brute force: cut short.
        summary=(
            f"Login {result} for user {(username or '?')[:40]}"
            f" on {(service or '?')[:40]} from {src_ip}"
        ),
        fields={
            "event_type": jsonl.text(obj, "event_type"),
            "username": username,
            "result": result,
            "service": service,
            "request_id": jsonl.ident(obj, "request_id"),
            "authorized": authorized,
        },
        raw=line,
    )


def parse_line(line: str, incident_id: UUID) -> EvidenceEvent | None:
    return jsonl.to_evidence(parse, SOURCE, line, incident_id)


def query(
    path: str, src_ip: str, start: datetime, end: datetime, incident_id: UUID
) -> list[EvidenceEvent]:
    """Login events from src_ip with start <= ts <= end, in file order."""
    return jsonl.query(
        path, parse, SOURCE, incident_id, lambda r: r.src_ip == src_ip and start <= r.ts <= end
    )
