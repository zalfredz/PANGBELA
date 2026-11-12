"""Process log evidence tool: query by time range.

JSON Lines with the fields from docs/log-schema.md: timestamp, host, container_id, pid,
ppid, exe, parent_exe, cmdline, uid, request_id (only when the lab's instrumentation
writes it). Which sensor writes the file (Falco or a lab fallback) is still open (Q11).
"""

import posixpath
from datetime import datetime
from uuid import UUID

from app.evidence import jsonl
from app.evidence.store import EvidenceEvent

SOURCE = "process"
available = jsonl.available


def parse(line: str) -> jsonl.Record:
    obj = jsonl.load(line)
    ts = jsonl.timestamp(obj)
    pid = jsonl.integer(obj, "pid", required=True)
    exe = jsonl.text(obj, "exe", required=True)
    ppid = jsonl.integer(obj, "ppid")
    parent_exe = jsonl.text(obj, "parent_exe")
    uid = jsonl.ident(obj, "uid")
    host = jsonl.text(obj, "host")
    container_id = jsonl.text(obj, "container_id")
    # The lab's execution policy, written by the sensor that observed the process.
    # Anything but a JSON boolean counts as not stated.
    authorized = obj.get("authorized")
    if not isinstance(authorized, bool):
        authorized = None
    where = container_id[:12] if container_id else (host or "?")[:40]
    parent = posixpath.basename(parent_exe)[:60] if parent_exe else "?"
    return jsonl.Record(
        ts=ts,
        src_ip=None,
        # Names only: the command line can carry the attacker's payload and stays in raw.
        summary=(
            f"Process {posixpath.basename(exe)[:60]} pid {pid} started by {parent}"
            f" ppid {ppid if ppid is not None else '?'} uid {(uid or '?')[:20]} on {where}"
        ),
        fields={
            "host": host,
            "container_id": container_id,
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "parent_exe": parent_exe,
            "cmdline": jsonl.text(obj, "cmdline"),
            "uid": uid,
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
    """Process events with start <= ts <= end. src_ip is unused: a process has no
    client address, so the rules link it to a request instead."""
    return jsonl.query(path, parse, SOURCE, incident_id, lambda r: start <= r.ts <= end)
