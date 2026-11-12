import logging
import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field

from app import db, events
from app.api.errors import api_error
from app.config import settings
from app.events import broker
from app.ingest.auth_detect import ingest_auth, parse_lines
from app.ingest.eve_parser import EveParseError, is_alert, parse_alert
from app.ingest.grouping import group_alert

log = logging.getLogger(__name__)
router = APIRouter()


class IngestBody(BaseModel):
    events: list[Any] = Field(max_length=100)


class IngestResult(BaseModel):
    accepted: int
    ignored: int
    incident_ids: list[str]


class AuthIngestBody(BaseModel):
    # Raw lines, not parsed objects: evidence keeps the line exactly as the log wrote
    # it, so a line ingested here and the same line read from the file later dedupe.
    lines: list[Annotated[str, Field(max_length=16384)]] = Field(max_length=100)


def _check_token(token: str | None) -> None:
    if not settings.INGEST_TOKEN:
        # Without this check an empty configured token would match an empty header.
        raise api_error(503, "ingest_not_configured", "INGEST_TOKEN is not set on the server")
    if token is None or not secrets.compare_digest(token.encode(), settings.INGEST_TOKEN.encode()):
        raise api_error(401, "bad_ingest_token", "X-Ingest-Token is missing or wrong")


def _emit_added(added: list) -> None:
    # Called after commit, so a stream never shows evidence a rollback discarded.
    for ev, created_at in added:
        broker.emit(
            ev.incident_id, events.evidence_added(ev.id, ev.source, ev.ts, ev.summary, created_at)
        )


@router.post("/ingest/suricata", status_code=202, response_model=IngestResult)
def ingest_suricata(
    body: IngestBody,
    x_ingest_token: Annotated[str | None, Header()] = None,
) -> IngestResult:
    _check_token(x_ingest_token)

    alerts, ignored = [], 0
    for event in body.events:
        if not is_alert(event):
            ignored += 1
            continue
        try:
            alerts.append(parse_alert(event))
        except EveParseError as e:
            # One malformed line must not drop the rest of the shipper's batch.
            log.warning("ignored malformed alert: %s", e)
            ignored += 1

    incident_ids: list[str] = []
    added = []
    # One transaction for the batch: a DB error stores nothing, so the shipper can resend.
    signature_types = settings.signature_attack_types
    with db.engine.begin() as conn:
        for a in sorted(alerts, key=lambda a: a.ts):
            incident_id, new = group_alert(
                conn, a, settings.INCIDENT_GROUP_WINDOW_SECONDS, signature_types
            )
            added += new
            if str(incident_id) not in incident_ids:
                incident_ids.append(str(incident_id))
    _emit_added(added)
    return IngestResult(accepted=len(alerts), ignored=ignored, incident_ids=incident_ids)


@router.post("/ingest/auth", status_code=202, response_model=IngestResult)
def ingest_auth_log(
    body: AuthIngestBody,
    x_ingest_token: Annotated[str | None, Header()] = None,
) -> IngestResult:
    """Login events as auth log lines (docs/log-schema.md). Opens a brute_force
    incident once a source IP crosses the failure threshold."""
    _check_token(x_ingest_token)
    records, ignored = parse_lines(body.lines)
    if ignored:
        log.warning("ignored %d invalid auth log lines", ignored)
    with db.engine.begin() as conn:
        incident_ids, added = ingest_auth(conn, records, settings)
    _emit_added(added)
    return IngestResult(
        accepted=len(records), ignored=ignored, incident_ids=[str(i) for i in incident_ids]
    )
