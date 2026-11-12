"""Read-only patch lifecycle records from the operator-run lab executor.

The backend never applies a patch: this endpoint only stores what the executor did, so
the dashboard can show the decision, template, result and audit reference.
"""

import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import text

from app import db
from app.api.errors import api_error
from app.api.recommendations import Operator

router = APIRouter()


class PatchRunBody(BaseModel):
    template_id: str = Field(max_length=100)
    template_version: str = Field(max_length=20)
    target_id: str = Field(max_length=100)
    allowed: bool
    reason: str = Field(max_length=100)
    result: str = Field(max_length=40)
    audit_ref: str = Field(max_length=500)
    detail: dict[str, Any] = Field(default_factory=dict)


@router.post("/incidents/{incident_id}/patch-runs", status_code=201)
def record_patch_run(incident_id: UUID, body: PatchRunBody, _by: Operator) -> dict:
    with db.engine.begin() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM incidents WHERE id = :id"), {"id": incident_id}
        ).scalar()
        if exists is None:
            raise api_error(404, "incident_not_found", f"no incident with id {incident_id}")
        row = (
            conn.execute(
                text(
                    "INSERT INTO patch_runs (incident_id, template_id, template_version,"
                    " target_id, allowed, reason, result, audit_ref, detail)"
                    " VALUES (:incident, :tid, :tver, :target, :allowed, :reason, :result,"
                    " :audit, CAST(:detail AS jsonb)) RETURNING id, recorded_at"
                ),
                {
                    "incident": incident_id,
                    "tid": body.template_id,
                    "tver": body.template_version,
                    "target": body.target_id,
                    "allowed": body.allowed,
                    "reason": body.reason,
                    "result": body.result,
                    "audit": body.audit_ref,
                    "detail": json.dumps(body.detail),
                },
            )
            .mappings()
            .one()
        )
    return jsonable_encoder({"id": row["id"], "recorded_at": row["recorded_at"]})
