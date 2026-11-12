"""Shared reading for the JSON Lines log sources (docs/log-schema.md).

Each line is one JSON object with the field names the cybersec team listed for the
lab. The formats are agreed on paper only: check them against real lab files once
samples/ has them.
"""

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import UUID

from app.evidence.store import EvidenceEvent, EvidenceSource

log = logging.getLogger(__name__)


class LineError(ValueError):
    """The line is not a valid record for its source."""


@dataclass(frozen=True)
class Record:
    ts: datetime  # UTC
    src_ip: str | None
    summary: str  # written by our code; attacker-chosen parts are cut short
    fields: dict[str, Any]
    raw: str  # the line, unchanged

    def to_evidence(self, source: EvidenceSource, incident_id: UUID) -> EvidenceEvent:
        return EvidenceEvent(
            incident_id=incident_id,
            source=source,
            ts=self.ts,
            src_ip=self.src_ip,
            summary=self.summary,
            raw=self.raw,
            fields=self.fields,
        )


def available(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.R_OK)


def load(line: str) -> dict:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        raise LineError("not JSON") from e
    if not isinstance(obj, dict):
        raise LineError("not a JSON object")
    return obj


def timestamp(obj: dict) -> datetime:
    value = obj.get("timestamp")
    if not isinstance(value, str):
        raise LineError("timestamp missing")
    try:
        ts = datetime.fromisoformat(value)
    except ValueError as e:
        raise LineError("bad timestamp") from e
    if ts.tzinfo is None:
        # The schema requires an explicit offset; guessing a zone would shift correlation.
        raise LineError("timestamp has no UTC offset")
    return ts.astimezone(UTC)


def ip(obj: dict, key: str) -> str:
    try:
        return str(ip_address(obj[key]))
    except (KeyError, ValueError, TypeError) as e:
        raise LineError(f"bad or missing {key}") from e


def text(obj: dict, key: str, *, required: bool = False) -> str | None:
    value = obj.get(key)
    if isinstance(value, str) and value:
        return value
    if required:
        raise LineError(f"{key} missing")
    return None


def integer(obj: dict, key: str, *, required: bool = False) -> int | None:
    value = obj.get(key)
    # bool is an int subclass; a JSON true is never a pid or status code.
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if required:
        raise LineError(f"{key} missing or not an integer")
    return None


def ident(obj: dict, key: str) -> str | None:
    """An identifier that may be written as a string or a number (request_id, uid)."""
    value = obj.get(key)
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def to_evidence(
    parse: Callable[[str], Record], source: EvidenceSource, line: str, incident_id: UUID
) -> EvidenceEvent | None:
    try:
        return parse(line).to_evidence(source, incident_id)
    except LineError:
        return None


def query(
    path: str,
    parse: Callable[[str], Record],
    source: EvidenceSource,
    incident_id: UUID,
    keep: Callable[[Record], bool],
) -> list[EvidenceEvent]:
    """Records in file order for which keep() is true. Blank lines and lines starting
    with # are skipped; invalid lines are counted and logged, never stored."""
    events, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\r\n")
            if not line.strip() or line.startswith("#"):
                continue
            try:
                record = parse(line)
            except LineError:
                skipped += 1
                continue
            if keep(record):
                events.append(record.to_evidence(source, incident_id))
    if skipped:
        log.warning("%s %s: %d invalid lines skipped", source, path, skipped)
    return events
