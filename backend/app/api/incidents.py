"""Incident list, detail, live stream and rerun (spec section 8)."""

import asyncio
import base64
import binascii
import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from fastapi.encoders import jsonable_encoder
from sqlalchemy import Connection, text
from sse_starlette import EventSourceResponse, ServerSentEvent

from app import db, events, pamela
from app.api.errors import api_error
from app.config import settings
from app.events import Event, broker

router = APIRouter()

INCIDENT_COLUMNS = (
    "id, attack_type, status, severity, confidence::float8 AS confidence, confidence_level,"
    " evidence_coverage::float8 AS evidence_coverage, verification_state, scanner_likely,"
    " host(src_ip) AS src_ip, host(dest_ip) AS dest_ip, opened_by, first_seen, last_seen,"
    " summary, report_md, pipeline_state, provisional_status, provisional_severity,"
    " provisional_verification, provisional_at, created_at, updated_at"
)


Queue = Literal["needs_human", "pamela", "running", "done"]


def _queue_sql(cfg) -> str:
    """CASE expression putting each incident in exactly one dashboard queue:
    running (agents queued or working), pamela (PAMELA may handle every open item it
    can do), needs_human (a person must decide, or the run failed), done (nothing open).
    Severities are inlined from config, a fixed literal list, not user input."""
    sevs = ", ".join(f"'{s}'" for s in pamela.allowed_severities(cfg)) or "NULL"
    acts = ", ".join(f"'{a}'" for a in pamela.EXECUTABLE)
    pending = (
        "EXISTS (SELECT 1 FROM recommendations r WHERE r.incident_id = incidents.id"
        " AND r.status = 'pending'{extra})"
    )
    return (
        "CASE WHEN pipeline_state IN ('queued', 'running') THEN 'running'"
        " WHEN pipeline_state = 'failed' THEN 'needs_human'"
        f" WHEN {pending.format(extra='')} THEN"
        f"  CASE WHEN severity IN ({sevs})"
        f"   AND {pending.format(extra=f' AND r.action IN ({acts})')}"
        "   THEN 'pamela' ELSE 'needs_human' END"
        " ELSE 'done' END"
    )


def _encode_cursor(created_at: datetime, incident_id: UUID) -> str:
    raw = f"{created_at.isoformat()}|{incident_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        created, incident_id = base64.urlsafe_b64decode(cursor.encode()).decode().split("|")
        return datetime.fromisoformat(created), UUID(incident_id)
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise api_error(422, "invalid_request", "before: not a cursor from next_before") from e


@router.get("/incidents")
def list_incidents(
    status: Literal["benign", "suspected", "attempted", "confirmed"] | None = None,
    severity: Literal["none", "low", "medium", "high", "critical"] | None = None,
    attack_type: Literal["rce", "brute_force", "unknown"] | None = None,
    queue: Queue | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: str | None = None,
) -> dict:
    where, params = [], {"limit": limit}
    for name, value in (
        ("status", status),
        ("severity", severity),
        ("attack_type", attack_type),
        ("queue", queue),
    ):
        if value is not None:
            where.append(f"{name} = :{name}")
            params[name] = value
    if before is not None:
        params["c_created"], params["c_id"] = _decode_cursor(before)
        where.append("(created_at, id) < (:c_created, :c_id)")
    # The queue is computed, so the filters apply to a subquery that has it as a column.
    sql = (
        f"SELECT * FROM (SELECT {INCIDENT_COLUMNS}, {_queue_sql(settings)} AS queue"
        " FROM incidents) incidents"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC, id DESC LIMIT :limit"
    with db.engine.connect() as conn:
        items = [dict(r) for r in conn.execute(text(sql), params).mappings()]
    next_before = (
        _encode_cursor(items[-1]["created_at"], items[-1]["id"]) if len(items) == limit else None
    )
    return jsonable_encoder({"items": items, "next_before": next_before})


@router.get("/incidents/overview")
def overview() -> dict:
    """How many incidents sit in each dashboard queue (over all incidents, not a page)."""
    sql = (
        f"SELECT q, count(*) FROM (SELECT {_queue_sql(settings)} AS q FROM incidents) x GROUP BY q"
    )
    with db.engine.connect() as conn:
        counts = dict(conn.execute(text(sql)).all())
    return {q: counts.get(q, 0) for q in ("needs_human", "pamela", "running", "done")}


def _incident_or_404(conn: Connection, incident_id: UUID) -> dict:
    row = (
        conn.execute(
            text(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = :id"), {"id": incident_id}
        )
        .mappings()
        .first()
    )
    if row is None:
        raise api_error(404, "incident_not_found", f"no incident with id {incident_id}")
    return dict(row)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: UUID) -> dict:
    with db.engine.connect() as conn:
        incident = _incident_or_404(conn, incident_id)

        def rows(sql: str) -> list[dict]:
            return [dict(r) for r in conn.execute(text(sql), {"id": incident_id}).mappings()]

        detail = {
            "incident": incident,
            "alerts": rows(
                "SELECT id, ts, host(src_ip) AS src_ip, host(dest_ip) AS dest_ip, signature_id,"
                " signature, category, flow_id, raw_json, received_at"
                " FROM alerts WHERE incident_id = :id ORDER BY ts"
            ),
            "evidence": rows(
                "SELECT id, source, ts, host(src_ip) AS src_ip, summary, raw, fields,"
                " collected_by, created_at FROM evidence WHERE incident_id = :id ORDER BY ts, id"
            ),
            "agent_runs": rows(
                "SELECT id, agent, round, status, output_json, cited_evidence_ids, rules_conflict,"
                " model, latency_ms, error, started_at, finished_at"
                " FROM agent_runs WHERE incident_id = :id ORDER BY started_at"
            ),
            "recommendations": rows(
                "SELECT id, action, target, reason, status, decided_by, decided_at"
                " FROM recommendations WHERE incident_id = :id ORDER BY id"
            ),
            "actions": rows(
                "SELECT id, recommendation_id, action, target, by_pamela, executed_by,"
                " created_at, expires_at, fetched_at, reverted_at, reverted_by"
                " FROM actions WHERE incident_id = :id ORDER BY created_at"
            ),
        }
        # What approving would actually do: the target the code takes from the incident
        # (shown instead of the agent's text), or why it would stay a manual task.
        for rec in detail["recommendations"]:
            rec["system_target"], rec["manual_reason"] = pamela.code_target(
                conn, incident, rec["action"], settings
            )
        detail["pamela"] = {
            "blocked_reason": pamela.gate(incident, settings),
            "max_severity": settings.PAMELA_MAX_SEVERITY,
            "block_seconds": settings.BLOCK_DURATION_SECONDS,
        }
        detail["lab_last_pull_at"] = conn.execute(
            text("SELECT last_pull_at FROM lab_status WHERE id = 1")
        ).scalar()
    return jsonable_encoder(detail)


@router.post("/incidents/{incident_id}/rerun", status_code=202)
def rerun_incident(incident_id: UUID) -> dict:
    """Queue the incident again; the start-delay loop picks it up on its next tick."""
    with db.engine.begin() as conn:
        updated = conn.execute(
            text(
                "UPDATE incidents SET pipeline_state = 'queued', updated_at = now()"
                " WHERE id = :id AND pipeline_state <> 'running' RETURNING id"
            ),
            {"id": incident_id},
        ).scalar()
        if updated is None:
            _incident_or_404(conn, incident_id)
            raise api_error(409, "run_in_progress", "a pipeline run for this incident is running")
    return {"id": str(incident_id), "pipeline_state": "queued"}


def replay_events(conn: Connection, incident_id: UUID) -> list[Event]:
    """Everything recorded for the incident, rebuilt as stream events in time order."""
    out: list[Event] = []
    warning = (
        conn.execute(
            text(
                "SELECT provisional_status, provisional_severity, provisional_verification,"
                " provisional_at FROM incidents WHERE id = :id"
                " AND provisional_severity IN ('high', 'critical')"
            ),
            {"id": incident_id},
        )
        .mappings()
        .first()
    )
    if warning is not None:
        # Only the latest provisional assessment is stored, so only it replays.
        out.append(
            events.early_warning(
                warning["provisional_status"],
                warning["provisional_severity"],
                warning["provisional_verification"],
                warning["provisional_at"],
            )
        )
    for e in conn.execute(
        text("SELECT id, source, ts, summary, created_at FROM evidence WHERE incident_id = :id"),
        {"id": incident_id},
    ).mappings():
        out.append(
            events.evidence_added(e["id"], e["source"], e["ts"], e["summary"], e["created_at"])
        )
    for r in conn.execute(
        text(
            "SELECT agent, round, status, output_json, rules_conflict, error, started_at,"
            " finished_at FROM agent_runs WHERE incident_id = :id"
        ),
        {"id": incident_id},
    ).mappings():
        started, finished = r["started_at"], r["finished_at"]
        if r["agent"] == "rules":
            out.append(
                events.verdict(
                    {**r["output_json"], "rules_conflict": r["rules_conflict"]},
                    started,
                    finished,
                )
            )
            continue
        out.append(events.agent_started(r["agent"], r["round"], started))
        output = r["output_json"] if r["status"] == "ok" else None
        out.append(
            events.agent_finished(r["agent"], r["round"], started, finished, r["status"], output)
        )
        if r["status"] != "ok":
            out.append(events.pipeline_failed(r["agent"], r["error"] or "", started, finished))
    return sorted(out, key=lambda e: e.at)


def _sse(e: Event) -> ServerSentEvent:
    return ServerSentEvent(data=json.dumps(jsonable_encoder(e.data)), event=e.name)


@router.get("/incidents/{incident_id}/stream")
async def stream_incident(incident_id: UUID) -> EventSourceResponse:
    def check_exists() -> None:
        with db.engine.connect() as conn:
            _incident_or_404(conn, incident_id)

    await asyncio.to_thread(check_exists)

    async def stream() -> AsyncIterator[ServerSentEvent]:
        # Subscribe before reading the replay, so an event emitted in between is
        # queued rather than lost; keys drop the ones the replay already covers.
        queue, in_flight = broker.subscribe(incident_id)
        try:

            def load() -> list[Event]:
                with db.engine.connect() as conn:
                    return replay_events(conn, incident_id)

            replay = await asyncio.to_thread(load)
            seen = {e.key for e in replay}
            finished_runs = {
                e.key.removeprefix("agent_finished:") for e in replay if e.name == "agent_finished"
            }
            if (
                in_flight is not None
                and in_flight.key not in seen
                and in_flight.key.removeprefix("agent_started:") not in finished_runs
            ):
                replay.append(in_flight)
                seen.add(in_flight.key)
            for e in replay:
                yield _sse(e)
            while True:
                e = await queue.get()
                if e.key in seen:
                    continue
                seen.add(e.key)
                yield _sse(e)
        finally:
            broker.unsubscribe(incident_id, queue)

    return EventSourceResponse(stream(), ping=15)
