"""Decisions on recommendations, PAMELA, and the enforcement list the lab pulls
(spec sections 8 and 13).

Approving a recommendation the system can carry out (block, monitor, reset password,
isolate) adds it to the enforcement list. Patching stays a task for a person.
"""

from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Header
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Connection, text

from app import db, pamela
from app.api.errors import api_error
from app.config import settings

router = APIRouter()

COLUMNS = "id, incident_id, action, target, reason, status, decided_by, decided_at"
ACTION_COLUMNS = (
    "id, incident_id, recommendation_id, action, target, by_pamela, executed_by, created_at,"
    " expires_at, fetched_at, reverted_at, reverted_by"
)
_INCIDENT = (
    "SELECT i.id, i.pipeline_state, i.confidence, i.severity, host(i.src_ip) AS src_ip,"
    " host(i.dest_ip) AS dest_ip FROM incidents i WHERE i.id = :id"
)


def _person(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("must not be blank")
    # Keeps the record honest: "PAMELA" in decided_by always means PAMELA did it.
    if value.casefold() == pamela.NAME.casefold():
        raise ValueError(f"{pamela.NAME} is reserved for the automatic helper")
    return value


class DecisionBody(BaseModel):
    decision: Literal["approved", "rejected"]
    decided_by: str = Field(min_length=1, max_length=100)

    _check = field_validator("decided_by")(_person)


class RevertBody(BaseModel):
    reverted_by: str = Field(min_length=1, max_length=100)

    _check = field_validator("reverted_by")(_person)


def _pending_or_error(conn: Connection, recommendation_id: UUID) -> dict:
    rec = (
        conn.execute(
            text(f"SELECT {COLUMNS} FROM recommendations WHERE id = :id FOR UPDATE"),
            {"id": recommendation_id},
        )
        .mappings()
        .first()
    )
    if rec is None:
        raise api_error(
            404, "recommendation_not_found", f"no recommendation with id {recommendation_id}"
        )
    if rec["status"] != "pending":
        raise api_error(409, "already_decided", f"recommendation is already {rec['status']}")
    return dict(rec)


def _approve(conn: Connection, rec: dict, by: str, by_pamela: bool, target: str | None) -> dict:
    row = dict(
        conn.execute(
            text(
                "UPDATE recommendations SET status = 'approved', decided_by = :by,"
                f" decided_at = now() WHERE id = :id RETURNING {COLUMNS}"
            ),
            {"by": by, "id": rec["id"]},
        )
        .mappings()
        .one()
    )
    action = None
    if target is not None:
        expires = (
            timedelta(seconds=settings.BLOCK_DURATION_SECONDS)
            if rec["action"] == "block_ip"
            else None
        )
        action = dict(
            conn.execute(
                text(
                    "INSERT INTO actions (incident_id, recommendation_id, action, target,"
                    " by_pamela, executed_by, expires_at) VALUES (:incident, :rec, :action,"
                    " :target, :by_pamela, :by, now() + CAST(:expires AS interval)) RETURNING "
                    + ACTION_COLUMNS
                ),
                {
                    "incident": rec["incident_id"],
                    "rec": rec["id"],
                    "action": rec["action"],
                    "target": target,
                    "by_pamela": by_pamela,
                    "by": by,
                    "expires": expires,
                },
            )
            .mappings()
            .one()
        )
    return {"recommendation": row, "action": action}


@router.post("/recommendations/{recommendation_id}/decision")
def decide(recommendation_id: UUID, body: DecisionBody) -> dict:
    """A person's decision. Approving also carries the action out when the system can;
    otherwise (patching, a protected IP, no single account) it is recorded for a person
    to do by hand. The response is the recommendation row plus "action" (or null)."""
    with db.engine.begin() as conn:
        rec = _pending_or_error(conn, recommendation_id)
        if body.decision == "rejected":
            row = (
                conn.execute(
                    text(
                        "UPDATE recommendations SET status = 'rejected', decided_by = :by,"
                        f" decided_at = now() WHERE id = :id RETURNING {COLUMNS}"
                    ),
                    {"by": body.decided_by, "id": rec["id"]},
                )
                .mappings()
                .one()
            )
            return jsonable_encoder({**row, "action": None})
        incident = conn.execute(text(_INCIDENT), {"id": rec["incident_id"]}).mappings().one()
        target, _ = pamela.code_target(conn, incident, rec["action"], settings)
        out = _approve(conn, rec, body.decided_by, False, target)
    return jsonable_encoder({**out["recommendation"], "action": out["action"]})


@router.post("/recommendations/{recommendation_id}/pamela")
def hand_to_pamela(recommendation_id: UUID) -> dict:
    """PAMELA carries the recommendation out, if the incident's severity allows it and
    the action has a target the code can take from the incident."""
    with db.engine.begin() as conn:
        rec = _pending_or_error(conn, recommendation_id)
        incident = conn.execute(text(_INCIDENT), {"id": rec["incident_id"]}).mappings().one()
        reason = pamela.gate(incident, settings)
        if reason is not None:
            raise api_error(403, reason, f"{pamela.NAME} may not act on this incident: {reason}")
        target, problem = pamela.code_target(conn, incident, rec["action"], settings)
        if problem is not None:
            raise api_error(422, problem, f"{pamela.NAME} cannot do this action: {problem}")
        out = _approve(conn, rec, pamela.NAME, True, target)
    return jsonable_encoder({**out["recommendation"], "action": out["action"]})


@router.post("/actions/{action_id}/revert")
def revert(action_id: UUID, body: RevertBody) -> dict:
    """Takes an action off the enforcement list; the lab drops it on its next pull."""
    with db.engine.begin() as conn:
        row = (
            conn.execute(
                text(
                    "UPDATE actions SET reverted_at = now(), reverted_by = :by"
                    f" WHERE id = :id AND reverted_at IS NULL RETURNING {ACTION_COLUMNS}"
                ),
                {"by": body.reverted_by, "id": action_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            exists = conn.execute(
                text("SELECT 1 FROM actions WHERE id = :id"), {"id": action_id}
            ).scalar()
            if exists is None:
                raise api_error(404, "action_not_found", f"no action with id {action_id}")
            raise api_error(409, "already_reverted", "action is already reverted")
    return jsonable_encoder(dict(row))


@router.get("/enforcement")
def enforcement(
    x_enforcement_token: Annotated[str | None, Header()] = None,
) -> dict:
    """The active actions, for the lab to apply. The list is the full desired state:
    whatever is not on it any more (reverted, expired) should be undone. Each pull is
    recorded, so the dashboard can show whether the lab is reading the list."""
    if not settings.ENFORCEMENT_TOKEN:
        raise api_error(503, "enforcement_disabled", "ENFORCEMENT_TOKEN is not set")
    if x_enforcement_token != settings.ENFORCEMENT_TOKEN:
        raise api_error(401, "invalid_token", "missing or wrong X-Enforcement-Token")
    with db.engine.begin() as conn:
        rows = (
            conn.execute(
                text(
                    "UPDATE actions SET fetched_at = coalesce(fetched_at, now())"
                    " WHERE reverted_at IS NULL AND (expires_at IS NULL OR expires_at > now())"
                    " RETURNING id, action, target, expires_at, created_at"
                )
            )
            .mappings()
            .all()
        )
        conn.execute(
            text(
                "INSERT INTO lab_status (id, last_pull_at) VALUES (1, now())"
                " ON CONFLICT (id) DO UPDATE SET last_pull_at = excluded.last_pull_at"
            )
        )
    out: dict[str, list] = {a: [] for a in pamela.EXECUTABLE}
    for r in sorted(rows, key=lambda r: r["created_at"]):
        out[r["action"]].append({"id": r["id"], "target": r["target"], "until": r["expires_at"]})
    return jsonable_encoder(out)
