"""Access log evidence tool: query by source IP and time range.

JSON Lines with the fields from docs/log-schema.md: timestamp, request_id, src_ip,
method, path, status, user_agent, service.
"""

from datetime import datetime
from urllib.parse import urlsplit
from uuid import UUID

from app.evidence import jsonl
from app.evidence.store import EvidenceEvent

SOURCE = "access_log"
available = jsonl.available


def parse(line: str) -> jsonl.Record:
    obj = jsonl.load(line)
    ts = jsonl.timestamp(obj)
    src_ip = jsonl.ip(obj, "src_ip")
    method = jsonl.text(obj, "method", required=True)
    target = urlsplit(jsonl.text(obj, "path", required=True))
    status = jsonl.integer(obj, "status", required=True)
    return jsonl.Record(
        ts=ts,
        src_ip=src_ip,
        # Method and path are attacker-chosen: cut short, the full line stays in raw.
        summary=f"HTTP {method[:16]} {target.path[:80]} -> {status} from {src_ip}",
        fields={
            "request_id": jsonl.ident(obj, "request_id"),
            "method": method,
            "path": target.path,
            "query": target.query,
            "status": status,
            "user_agent": jsonl.text(obj, "user_agent"),
            "service": jsonl.text(obj, "service"),
        },
        raw=line,
    )


def parse_line(line: str, incident_id: UUID) -> EvidenceEvent | None:
    return jsonl.to_evidence(parse, SOURCE, line, incident_id)


def query(
    path: str, src_ip: str, start: datetime, end: datetime, incident_id: UUID
) -> list[EvidenceEvent]:
    """Requests from src_ip with start <= ts <= end, in file order."""
    return jsonl.query(
        path, parse, SOURCE, incident_id, lambda r: r.src_ip == src_ip and start <= r.ts <= end
    )
