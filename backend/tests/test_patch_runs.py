"""Patch lifecycle records are operator-written and read-only for the dashboard."""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import settings
from app.main import app
from tests.support import AUTH
from tests.test_api import make_incident

BODY = {
    "template_id": "v1_sanitize_ping",
    "template_version": "1",
    "target_id": "lab-web",
    "allowed": True,
    "reason": "eligible",
    "result": "applied",
    "audit_ref": "lab/patch/audit/x.json",
    "detail": {"checks": [{"check": "health", "pass": True}]},
}


def test_patch_run_requires_operator_token(engine):
    incident = make_incident(engine)
    r = TestClient(app).post(f"/incidents/{incident}/patch-runs", json=BODY)
    assert r.status_code == 401


def test_patch_run_fails_closed_without_operators(engine, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_TOKENS", "")
    incident = make_incident(engine)
    r = TestClient(app).post(
        f"/incidents/{incident}/patch-runs", json=BODY, headers={"X-Operator-Token": "x"}
    )
    assert r.status_code == 503


def test_unknown_incident_is_404(engine):
    r = TestClient(app).post(f"/incidents/{uuid4()}/patch-runs", json=BODY, headers=AUTH)
    assert r.status_code == 404


def test_recorded_run_is_visible_in_incident_detail(engine):
    incident = make_incident(engine)
    client = TestClient(app)
    r = client.post(f"/incidents/{incident}/patch-runs", json=BODY, headers=AUTH)
    assert r.status_code == 201
    detail = client.get(f"/incidents/{incident}").json()
    run = detail["patch_runs"][0]
    assert (run["template_id"], run["result"], run["allowed"]) == (
        "v1_sanitize_ping",
        "applied",
        True,
    )
    assert run["detail"]["checks"][0]["pass"] is True


def test_denial_reason_is_preserved(engine):
    incident = make_incident(engine)
    body = {**BODY, "allowed": False, "reason": "needs_human", "result": "denied"}
    TestClient(app).post(f"/incidents/{incident}/patch-runs", json=body, headers=AUTH)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT reason, allowed, result FROM patch_runs WHERE incident_id = :id"),
            {"id": incident},
        ).one()
    assert tuple(row) == ("needs_human", False, "denied")


@pytest.mark.parametrize("field", ["template_id", "reason", "result"])
def test_required_fields_are_validated(engine, field):
    incident = make_incident(engine)
    body = {k: v for k, v in BODY.items() if k != field}
    r = TestClient(app).post(f"/incidents/{incident}/patch-runs", json=body, headers=AUTH)
    assert r.status_code == 422
