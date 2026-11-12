"""PAMELA, decisions that carry actions out, the enforcement list and dashboard queues
(spec section 13). Pipeline runs use the fake LLM from test_pipeline: the fixture
alert is a command injection attempt the rules settle as attempted, severity medium."""

import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import settings
from app.main import app
from tests.support import AUTH, OPERATOR_NAME
from tests.test_api import make_incident
from tests.test_pipeline import detection_reply, forensics_reply, investigation_reply, run

SRC = "198.51.100.23"


def decision_with(*recs):
    return json.dumps(
        {
            "proposed_status": "attempted",
            "proposed_severity": "medium",
            "summary": "One sentence.",
            "report_md": "## What happened\n...",
            "recommendations": [{"action": a, "target": t, "reason": "because"} for a, t in recs],
        }
    )


# The agent names a different IP on purpose: the action must use the incident's.
DEFAULT_RECS = (("block_ip", "10.9.9.9"), ("patch_endpoint", "/ping"))


@pytest.fixture
def client(engine):
    return TestClient(app)


def analysed(engine, recs=DEFAULT_RECS):
    incident_id = make_incident(engine)
    run(
        incident_id,
        [detection_reply, investigation_reply(), forensics_reply, decision_with(*recs)],
    )
    return incident_id


def recs_by_action(client, incident_id):
    return {
        r["action"]: r for r in client.get(f"/incidents/{incident_id}").json()["recommendations"]
    }


def set_incident(engine, incident_id, **cols):
    sets = ", ".join(f"{k} = :{k}" for k in cols)
    with engine.begin() as conn:
        conn.execute(
            text(f"UPDATE incidents SET {sets} WHERE id = :id"), {**cols, "id": incident_id}
        )


# --- PAMELA --------------------------------------------------------------------------


def test_pamela_blocks_the_incident_source_not_the_agent_target(client, engine):
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    assert rec["system_target"] == SRC and rec["manual_reason"] is None

    r = client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "approved" and body["decided_by"] == "PAMELA"
    assert body["action"]["target"] == SRC
    assert body["action"]["by_pamela"] is True
    assert body["action"]["expires_at"] is not None


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_pamela_refuses_high_and_critical_severity(client, engine, severity):
    incident_id = analysed(engine)
    set_incident(engine, incident_id, severity=severity)
    rec = recs_by_action(client, incident_id)["block_ip"]
    r = client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH)
    assert r.status_code == 403 and r.json()["error"] == "needs_human"
    assert recs_by_action(client, incident_id)["block_ip"]["status"] == "pending"
    detail = client.get(f"/incidents/{incident_id}").json()
    assert detail["pamela"]["blocked_reason"] == "needs_human"


def test_critical_rce_patch_cannot_be_auto_applied(client, engine):
    # Patch execution does not exist: even at low/medium it stays a manual task, and at
    # critical PAMELA is refused before the action type is even considered.
    incident_id = analysed(engine)
    set_incident(engine, incident_id, severity="critical")
    patch = recs_by_action(client, incident_id)["patch_endpoint"]
    r = client.post(f"/recommendations/{patch['id']}/pamela", headers=AUTH)
    assert (r.status_code, r.json()["error"]) == (403, "needs_human")
    assert recs_by_action(client, incident_id)["patch_endpoint"]["status"] == "pending"


def test_pamela_refuses_while_agents_run(client, engine):
    incident_id = analysed(engine)
    set_incident(engine, incident_id, pipeline_state="running")
    rec = recs_by_action(client, incident_id)["block_ip"]
    r = client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH)
    assert r.status_code == 403 and r.json()["error"] == "not_decided"


def test_pamela_cannot_patch(client, engine):
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["patch_endpoint"]
    assert rec["manual_reason"] == "manual_only"
    r = client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH)
    assert r.status_code == 422 and r.json()["error"] == "manual_only"


def test_reset_password_needs_one_account_in_the_evidence(client, engine):
    # The RCE fixture has no auth log evidence, so there is no account to reset.
    incident_id = analysed(engine, (("reset_password", "admin"),))
    rec = recs_by_action(client, incident_id)["reset_password"]
    assert rec["manual_reason"] == "no_account"
    assert client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH).status_code == 422


def test_protected_ip_is_never_blocked(client, engine, monkeypatch):
    monkeypatch.setattr(settings, "PROTECTED_IPS", "198.51.100.0/24")
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    assert rec["manual_reason"] == "protected_ip"
    assert client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH).status_code == 422
    # A person may still approve; it is recorded, but nothing goes on the list.
    r = client.post(
        f"/recommendations/{rec['id']}/decision", json={"decision": "approved"}, headers=AUTH,
    )
    assert r.status_code == 200 and r.json()["action"] is None


def test_pamela_off_when_max_severity_none(client, engine, monkeypatch):
    monkeypatch.setattr(settings, "PAMELA_MAX_SEVERITY", "none")
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    assert client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH).status_code == 403


def test_pamela_on_decided_recommendation_is_409(client, engine):
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    assert client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH).status_code == 200
    assert client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH).status_code == 409


def test_pamela_unknown_recommendation_is_404(client):
    assert client.post(f"/recommendations/{uuid4()}/pamela", headers=AUTH).status_code == 404


# --- decisions by a person -----------------------------------------------------------


def test_person_approves_high_severity_and_it_is_carried_out(client, engine):
    incident_id = analysed(engine)
    set_incident(engine, incident_id, severity="high")
    rec = recs_by_action(client, incident_id)["block_ip"]
    r = client.post(
        f"/recommendations/{rec['id']}/decision", json={"decision": "approved"}, headers=AUTH,
    )
    assert r.status_code == 200
    assert r.json()["action"]["executed_by"] == OPERATOR_NAME
    assert r.json()["action"]["by_pamela"] is False


def test_reject_carries_nothing_out(client, engine):
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    r = client.post(
        f"/recommendations/{rec['id']}/decision", json={"decision": "rejected"}, headers=AUTH,
    )
    assert r.json()["status"] == "rejected" and r.json()["action"] is None
    assert client.get(f"/incidents/{incident_id}").json()["actions"] == []


def test_decision_requires_an_operator_token(client, engine):
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    path = f"/recommendations/{rec['id']}/decision"
    body = {"decision": "approved"}
    assert client.post(path, json=body).status_code == 401
    assert client.post(path, json=body, headers={"X-Operator-Token": "x" * 40}).status_code == 401


def test_decision_body_cannot_choose_the_operator_name(client, engine):
    # A caller with a valid token still cannot sign as somebody else: the name is the
    # one the server maps to the token, and the body field is ignored.
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    r = client.post(
        f"/recommendations/{rec['id']}/decision",
        json={"decision": "approved", "decided_by": "PAMELA"},
        headers=AUTH,
    )
    assert r.status_code == 200
    assert r.json()["decided_by"] == OPERATOR_NAME


def test_response_endpoints_fail_closed_without_operator_tokens(client, engine, monkeypatch):
    monkeypatch.setattr(settings, "OPERATOR_TOKENS", "")
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    assert client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH).status_code == 503
    assert (
        client.post(
            f"/recommendations/{rec['id']}/decision",
            json={"decision": "approved"},
            headers=AUTH,
        ).status_code
        == 503
    )


def test_rerun_does_not_ask_again_about_a_decided_action(client, engine):
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH)
    run(
        incident_id,
        [detection_reply, investigation_reply(), forensics_reply, decision_with(*DEFAULT_RECS)],
    )
    recs = client.get(f"/incidents/{incident_id}").json()["recommendations"]
    assert sorted((r["action"], r["status"]) for r in recs) == [
        ("block_ip", "approved"),
        ("patch_endpoint", "pending"),
    ]


# --- revert and the enforcement list --------------------------------------------------


def test_enforcement_off_without_token(client, monkeypatch):
    monkeypatch.setattr(settings, "ENFORCEMENT_TOKEN", "")
    assert client.get("/enforcement").status_code == 503


def test_enforcement_rejects_wrong_token(client, monkeypatch):
    monkeypatch.setattr(settings, "ENFORCEMENT_TOKEN", "right")
    r = client.get("/enforcement", headers={"X-Enforcement-Token": "wrong"})
    assert r.status_code == 401


def test_enforcement_lists_active_actions_and_records_the_pull(client, engine, monkeypatch):
    monkeypatch.setattr(settings, "ENFORCEMENT_TOKEN", "right")
    incident_id = analysed(engine, (("block_ip", SRC), ("monitor", SRC)))
    recs = recs_by_action(client, incident_id)
    blocked = client.post(
        f"/recommendations/{recs['block_ip']['id']}/pamela", headers=AUTH
    ).json()["action"]
    watched = client.post(
        f"/recommendations/{recs['monitor']['id']}/pamela", headers=AUTH
    ).json()["action"]
    assert client.get(f"/incidents/{incident_id}").json()["lab_last_pull_at"] is None

    r = client.get("/enforcement", headers={"X-Enforcement-Token": "right"})
    assert r.status_code == 200
    body = r.json()
    assert [a["target"] for a in body["block_ip"]] == [SRC]
    assert [a["id"] for a in body["monitor"]] == [watched["id"]]
    detail = client.get(f"/incidents/{incident_id}").json()
    assert detail["lab_last_pull_at"] is not None
    assert all(a["fetched_at"] is not None for a in detail["actions"])

    # Reverted and expired rows drop off the list.
    assert (
        client.post(f"/actions/{blocked['id']}/revert", headers=AUTH).status_code
        == 200
    )
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE actions SET expires_at = now() - interval '1 second'"
                " WHERE action = 'monitor'"
            )
        )
    body = client.get("/enforcement", headers={"X-Enforcement-Token": "right"}).json()
    assert body["block_ip"] == [] and body["monitor"] == []


def test_revert_twice_is_409(client, engine):
    incident_id = analysed(engine)
    rec = recs_by_action(client, incident_id)["block_ip"]
    action = client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH).json()["action"]
    assert client.post(f"/actions/{action['id']}/revert", headers=AUTH).status_code == 200
    assert client.post(f"/actions/{action['id']}/revert", headers=AUTH).status_code == 409
    assert client.post(f"/actions/{uuid4()}/revert", headers=AUTH).status_code == 404


# --- dashboard queues ----------------------------------------------------------------


def queues(client):
    return client.get("/incidents/overview").json()


def test_queues_follow_the_incident(client, engine):
    assert queues(client) == {"needs_human": 0, "pamela": 0, "running": 0, "done": 0}
    incident_id = make_incident(engine)
    assert queues(client)["running"] == 1  # queued for the agents

    run(
        incident_id,
        [detection_reply, investigation_reply(), forensics_reply, decision_with(*DEFAULT_RECS)],
    )
    assert queues(client)["pamela"] == 1
    item = client.get("/incidents", params={"queue": "pamela"}).json()["items"][0]
    assert item["id"] == str(incident_id) and item["queue"] == "pamela"

    # PAMELA did its part; the patch is left for a person.
    rec = recs_by_action(client, incident_id)["block_ip"]
    client.post(f"/recommendations/{rec['id']}/pamela", headers=AUTH)
    assert queues(client)["needs_human"] == 1

    patch = recs_by_action(client, incident_id)["patch_endpoint"]
    client.post(
        f"/recommendations/{patch['id']}/decision", json={"decision": "approved"}, headers=AUTH,
    )
    assert queues(client)["done"] == 1


def test_high_severity_goes_to_a_person(client, engine):
    incident_id = analysed(engine)
    set_incident(engine, incident_id, severity="high")
    assert queues(client)["needs_human"] == 1
    assert client.get("/incidents", params={"queue": "pamela"}).json()["items"] == []


def test_failed_run_needs_a_person(client, engine):
    incident_id = make_incident(engine)
    set_incident(engine, incident_id, pipeline_state="failed")
    assert queues(client)["needs_human"] == 1
