"""Section 8 endpoints other than ingest: incidents, rerun, decisions, test results, and
the stream's replay. Pipeline runs use the fake LLM from test_pipeline."""

import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api.incidents import replay_events
from app.events import broker
from app.graph.pipeline import PipelineFailed
from app.ingest.eve_parser import parse_alert
from app.ingest.grouping import group_alert
from app.main import app
from tests.fixtures.eve_alerts import alert
from tests.support import AUTH, OPERATOR_NAME
from tests.test_pipeline import (
    decision_reply,
    detection_reply,
    forensics_reply,
    investigation_reply,
    run,
)

REPLIES = [detection_reply, investigation_reply(), forensics_reply, decision_reply("attempted")]


@pytest.fixture
def client(engine):
    # Not used as a context manager, so the lifespan (and its start-delay loop) never runs.
    return TestClient(app)


def make_incident(engine, ts="2026-11-11T02:00:00.000000+0000", src="198.51.100.23"):
    with engine.begin() as conn:
        incident_id, _ = group_alert(conn, parse_alert(alert(ts, src=src)), 600)
    return incident_id


# --- list ----------------------------------------------------------------------------


def test_list_empty(client):
    assert client.get("/incidents").json() == {"items": [], "next_before": None}


def test_list_filters(client, engine):
    a = make_incident(engine, src="198.51.100.1")
    make_incident(engine, src="198.51.100.2")
    with engine.begin() as conn:
        conn.execute(text("UPDATE incidents SET status = 'attempted' WHERE id = :id"), {"id": a})
    items = client.get("/incidents", params={"status": "attempted"}).json()["items"]
    assert [i["id"] for i in items] == [str(a)]
    assert items[0]["src_ip"] == "198.51.100.1"


def test_list_rejects_unknown_filter_value(client):
    r = client.get("/incidents", params={"status": "pwned"})
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_request"


def test_list_paginates_with_cursor(client, engine):
    ids = [make_incident(engine, src=f"198.51.100.{i}") for i in range(1, 6)]
    seen, before = [], None
    while True:
        params = {"limit": 2, **({"before": before} if before else {})}
        page = client.get("/incidents", params=params).json()
        seen += [i["id"] for i in page["items"]]
        before = page["next_before"]
        if before is None:
            break
    assert seen == [str(i) for i in reversed(ids)]  # newest first, no repeats or gaps


def test_list_rejects_bad_cursor(client):
    assert client.get("/incidents", params={"before": "!!!"}).status_code == 422


# --- detail --------------------------------------------------------------------------


def test_detail_unknown_is_404(client):
    r = client.get(f"/incidents/{uuid4()}")
    assert r.status_code == 404
    assert r.json()["error"] == "incident_not_found"


def test_detail_after_run(client, engine):
    incident_id = make_incident(engine)
    run(incident_id, list(REPLIES))
    body = client.get(f"/incidents/{incident_id}").json()
    assert set(body) == {
        "incident",
        "alerts",
        "evidence",
        "agent_runs",
        "recommendations",
        "actions",
        "pamela",
        "lab_last_pull_at",
    }
    assert body["incident"]["status"] == "attempted"
    assert body["incident"]["confidence"] == 0.67  # 2 of 3 sources, decision agreed
    assert body["incident"]["verification_state"] == "insufficient_telemetry"  # no process log
    assert body["incident"]["confidence_level"] == "low"
    assert body["incident"]["opened_by"] == "suricata"
    assert len(body["alerts"]) == 1
    assert [r["agent"] for r in body["agent_runs"]] == [
        "detection",
        "investigation",
        "forensics",
        "decision",
        "rules",
    ]
    assert body["recommendations"][0]["status"] == "pending"


# --- rerun ---------------------------------------------------------------------------


def test_rerun_queues_finished_incident(client, engine):
    incident_id = make_incident(engine)
    run(incident_id, list(REPLIES))
    r = client.post(f"/incidents/{incident_id}/rerun")
    assert r.status_code == 202
    assert client.get(f"/incidents/{incident_id}").json()["incident"]["pipeline_state"] == "queued"


def test_rerun_while_running_is_409(client, engine):
    incident_id = make_incident(engine)
    with engine.begin() as conn:
        conn.execute(text("UPDATE incidents SET pipeline_state = 'running'"))
    r = client.post(f"/incidents/{incident_id}/rerun")
    assert r.status_code == 409
    assert r.json()["error"] == "run_in_progress"


def test_rerun_unknown_is_404(client):
    assert client.post(f"/incidents/{uuid4()}/rerun").status_code == 404


# --- recommendation decisions --------------------------------------------------------


def first_recommendation(client, engine) -> str:
    incident_id = make_incident(engine)
    run(incident_id, list(REPLIES))
    return client.get(f"/incidents/{incident_id}").json()["recommendations"][0]["id"]


def test_decision_records_and_returns_row(client, engine):
    rec = first_recommendation(client, engine)
    r = client.post(
        f"/recommendations/{rec}/decision", json={"decision": "approved"}, headers=AUTH
    )
    assert r.status_code == 200
    body = r.json()
    assert (body["status"], body["decided_by"]) == ("approved", OPERATOR_NAME)
    assert body["decided_at"] is not None


def test_second_decision_is_409(client, engine):
    rec = first_recommendation(client, engine)
    body = {"decision": "rejected"}
    client.post(f"/recommendations/{rec}/decision", json=body, headers=AUTH)
    r = client.post(f"/recommendations/{rec}/decision", json=body, headers=AUTH)
    assert r.status_code == 409
    assert r.json()["error"] == "already_decided"


@pytest.mark.parametrize("body", [{"decision": "maybe"}, {}])
def test_decision_validation(client, engine, body):
    rec = first_recommendation(client, engine)
    assert (
        client.post(f"/recommendations/{rec}/decision", json=body, headers=AUTH).status_code == 422
    )


def test_decision_unknown_is_404(client):
    r = client.post(
        f"/recommendations/{uuid4()}/decision", json={"decision": "approved"}, headers=AUTH
    )
    assert r.status_code == 404


def test_operator_tokens_must_be_name_token_pairs():
    from app.config import Settings

    for value in (
        "alice",
        "alice:short",
        "PAMELA:" + "x" * 40,
        "a:" + "x" * 40 + ",a:" + "y" * 40,
    ):
        with pytest.raises(ValueError):
            Settings(OPERATOR_TOKENS=value)


# --- test results --------------------------------------------------------------------


def add_test_case(engine, case_id, src_ip, expected):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO test_cases (id, scenario, src_ip, attack_type, presence, outcome,"
                " expected_status, expected_severity)"
                " VALUES (:id, 'test', CAST(:ip AS inet), 'rce', 'attack', 'failed', :st, 'medium')"
            ),
            {"id": case_id, "ip": src_ip, "st": expected},
        )


def test_results_empty_without_test_cases(client):
    assert client.get("/tests/results").json() == []


def test_results_match_by_src_ip(client, engine):
    add_test_case(engine, "T1", "198.51.100.23", "attempted")
    add_test_case(engine, "T2", "198.51.100.77", "confirmed")
    add_test_case(engine, "T3", "198.51.100.88", "benign")
    incident_id = make_incident(engine)  # from 198.51.100.23
    run(incident_id, list(REPLIES))
    make_incident(engine, src="198.51.100.77")  # never run: still queued
    rows = {r["test_case"]: r for r in client.get("/tests/results").json()}
    assert rows["T1"] == {
        "test_case": "T1",
        "incident_id": str(incident_id),
        "expected_status": "attempted",
        "actual_status": "attempted",
        "match": True,
    }
    assert rows["T2"]["actual_status"] is None and rows["T2"]["match"] is False
    assert rows["T3"]["incident_id"] is None and rows["T3"]["match"] is False


# --- stream --------------------------------------------------------------------------


def test_stream_unknown_is_404(client):
    assert client.get(f"/incidents/{uuid4()}/stream").status_code == 404


def test_replay_lists_a_finished_run_in_order(engine):
    incident_id = make_incident(engine)
    run(incident_id, list(REPLIES))
    with engine.connect() as conn:
        replay = replay_events(conn, incident_id)
    names = [(e.name, e.data.get("agent") or e.data.get("source")) for e in replay]
    assert names == [
        ("evidence_added", "suricata"),  # stored at ingest
        ("agent_started", "detection"),
        ("agent_finished", "detection"),
        ("evidence_added", "access_log"),  # fetched after detection, before investigation
        ("evidence_added", "access_log"),
        ("agent_started", "investigation"),
        ("agent_finished", "investigation"),
        ("agent_started", "forensics"),
        ("agent_finished", "forensics"),
        ("agent_started", "decision"),
        ("agent_finished", "decision"),
        ("verdict", None),
    ]
    assert replay[-1].data == {
        "status": "attempted",
        "severity": "medium",
        "confidence": 0.67,
        "confidence_level": "low",
        "evidence_coverage": 0.67,
        "verification_state": "insufficient_telemetry",
        "rules_conflict": None,
    }
    assert all(json.dumps(e.data) for e in replay)  # every payload is JSON-serializable


def test_replay_keys_match_live_events(engine, monkeypatch):
    """A stream drops a live event whose key is already in its replay, so the two must agree."""
    captured = []
    monkeypatch.setattr(broker, "emit", lambda incident_id, e: captured.append(e))
    incident_id = make_incident(engine)
    run(incident_id, list(REPLIES))
    with engine.connect() as conn:
        replay = replay_events(conn, incident_id)
    # Same events, same order, apart from the ingest evidence (emitted by the API, not here).
    assert [e.key for e in captured] == [
        e.key for e in replay if e.data.get("source") != "suricata"
    ]
    assert [e.data for e in captured] == [
        e.data for e in replay if e.data.get("source") != "suricata"
    ]


def test_failed_run_replays_pipeline_failed(engine):
    incident_id = make_incident(engine)
    with pytest.raises(PipelineFailed):
        run(incident_id, ["not json", "still not json"])
    with engine.connect() as conn:
        replay = replay_events(conn, incident_id)
    assert [e.name for e in replay][-2:] == ["agent_finished", "pipeline_failed"]
    assert replay[-1].data["agent"] == "detection"
