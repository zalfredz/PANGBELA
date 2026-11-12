"""Whole pipeline against the test database with a fake LLM: routing, evidence storage,
agent_runs, the rules gate writing the status, and failure handling."""

import json
import re
from pathlib import Path

import pytest
from sqlalchemy import text

from app.config import Settings
from app.graph.pipeline import AlreadyRunning, PipelineFailed, run_pipeline
from app.ingest.eve_parser import parse_alert
from app.ingest.grouping import group_alert
from app.llm.client import LLMClient
from tests.fake_llm import FakeSDK
from tests.fixtures.eve_alerts import alert

ACCESS_LOG = str(Path(__file__).parent / "fixtures" / "access_rce.jsonl")
PAYLOAD = "/ping?host=127.0.0.1;id"
EV_ID = re.compile(r"\[(ev_[0-9a-f]{12})\]")

CFG = Settings(
    ACCESS_LOG_PATH=ACCESS_LOG,
    AUTH_LOG_PATH="/nonexistent/auth.log",
    PROCESS_LOG_PATH="/nonexistent/process.log",
    MAX_EVIDENCE_ROUNDS=2,
    LLM_SCHEMA_RETRIES=1,
    LLM_MODEL="fake-model",
)


def ids_in(kwargs) -> list[str]:
    return EV_ID.findall(kwargs["messages"][1]["content"])


def finding(ids):
    return [{"claim": "seen in evidence", "evidence_ids": ids[:1]}]


def detection_reply(kwargs):
    return json.dumps(
        {
            "attack_type": "rce",
            "hypothesis": "command injection in /ping",
            "indicators": finding(ids_in(kwargs)),
            "suggested_sources": ["access_log", "process"],
        }
    )


def investigation_reply(ruled_benign=False, requests=()):
    def reply(kwargs):
        return json.dumps(
            {
                "hypothesis_holds": not ruled_benign,
                "findings": finding(ids_in(kwargs)),
                "counter_evidence": [],
                "scanner_likely": False,
                "ruled_benign": ruled_benign,
                "evidence_requests": [{"source": s, "reason": "need it"} for s in requests],
                "proposed_status": "benign" if ruled_benign else "attempted",
            }
        )

    return reply


def forensics_reply(kwargs):
    return json.dumps(
        {
            "impact_found": False,
            "impact_type": "none",
            "findings": finding(ids_in(kwargs)),
            "checked_sources": ["access_log"],
            "missing_sources": ["auth_log", "process"],
        }
    )


def decision_reply(status):
    return json.dumps(
        {
            "proposed_status": status,
            "proposed_severity": "critical",
            "summary": "One sentence.",
            "report_md": "## What happened\n...",
            "recommendations": [
                {"action": "block_ip", "target": "198.51.100.23", "reason": "attacker"}
            ],
        }
    )


@pytest.fixture
def incident(engine):
    with engine.begin() as conn:
        incident_id, _ = group_alert(
            conn, parse_alert(alert("2026-11-11T02:00:00.000000+0000")), 600
        )
        return incident_id


def run(incident, replies):
    sdk = FakeSDK(replies)
    run_pipeline(incident, LLMClient(CFG, sdk=sdk), CFG)
    return sdk


def row(engine, sql, **params):
    with engine.connect() as conn:
        return conn.execute(text(sql), params).mappings().one()


def rows(engine, sql, **params):
    with engine.connect() as conn:
        return conn.execute(text(sql), params).mappings().all()


def test_full_run_rules_override_decision(engine, incident):
    sdk = run(
        incident,
        [detection_reply, investigation_reply(), forensics_reply, decision_reply("confirmed")],
    )
    inc = row(engine, "SELECT * FROM incidents WHERE id = :id", id=incident)
    # The access log shows the payload but no process log exists: rules cap at attempted.
    assert inc["status"] == "attempted"
    assert inc["severity"] == "medium"
    assert inc["attack_type"] == "rce"
    assert float(inc["confidence"]) == 0.47  # 2 of 3 sources, minus 0.2 for the conflict
    assert inc["pipeline_state"] == "done"
    assert inc["summary"] == "One sentence."

    runs = rows(engine, "SELECT * FROM agent_runs ORDER BY started_at")
    assert [r["agent"] for r in runs] == [
        "detection",
        "investigation",
        "forensics",
        "decision",
        "rules",
    ]
    assert all(r["status"] == "ok" for r in runs)
    assert runs[-1]["rules_conflict"] == "proposed confirmed, rules allow attempted"
    assert runs[-1]["output_json"]["facts"]["payload_logged"] is True
    assert runs[0]["cited_evidence_ids"] and runs[0]["model"] == "fake-model"

    access = rows(engine, "SELECT * FROM evidence WHERE source = 'access_log'")
    # Two attacker lines fall in the padded window; the other client's line is filtered out.
    assert len(access) == 2
    assert {r["collected_by"] for r in access} == {"investigation"}

    recs = rows(engine, "SELECT * FROM recommendations")
    assert [(r["action"], r["status"]) for r in recs] == [("block_ip", "pending")]
    assert len(sdk.calls) == 4


def test_attacker_content_only_inside_untrusted_block(engine, incident):
    sdk = run(
        incident,
        [detection_reply, investigation_reply(), forensics_reply, decision_reply("attempted")],
    )
    for call in sdk.calls:
        system, user = call["messages"][0]["content"], call["messages"][1]["content"]
        assert PAYLOAD not in system
        if PAYLOAD in user:
            assert user.index("<untrusted_data>") < user.index(PAYLOAD)
            assert user.index(PAYLOAD) < user.rindex("</untrusted_data>")


def test_ruled_benign_skips_forensics(engine, incident):
    run(
        incident,
        [detection_reply, investigation_reply(ruled_benign=True), decision_reply("benign")],
    )
    inc = row(engine, "SELECT status, severity FROM incidents WHERE id = :id", id=incident)
    assert (inc["status"], inc["severity"]) == ("benign", "none")
    agents = [r["agent"] for r in rows(engine, "SELECT agent FROM agent_runs ORDER BY started_at")]
    assert "forensics" not in agents
    rules = row(engine, "SELECT rules_conflict FROM agent_runs WHERE agent = 'rules'")
    assert rules["rules_conflict"] is None


def investigation_rounds(engine) -> list[int]:
    inv = rows(
        engine, "SELECT round FROM agent_runs WHERE agent = 'investigation' ORDER BY started_at"
    )
    return [r["round"] for r in inv]


@pytest.mark.parametrize(
    "requested",
    [
        ["auth_log"],  # unavailable: no log to read
        ["access_log"],  # already queried over the same time range in round 1
    ],
)
def test_request_that_cannot_add_evidence_gets_no_extra_round(engine, incident, requested):
    run(
        incident,
        [
            detection_reply,
            investigation_reply(requests=requested),
            forensics_reply,
            decision_reply("attempted"),
        ],
    )
    assert investigation_rounds(engine) == [1]


@pytest.fixture
def process_source(monkeypatch):
    """Make 'process' a readable source that returns no lines, so a request for it is new."""
    import app.graph.pipeline as pipeline

    real_sources, real_readable = pipeline.log_sources, pipeline.readable_sources
    queried = []

    def query(path, src_ip, start, end, incident_id):
        queried.append(path)
        return []

    monkeypatch.setattr(
        pipeline,
        "log_sources",
        lambda cfg: {**real_sources(cfg), "process": ("proc.log", lambda p: True, query)},
    )
    monkeypatch.setattr(
        pipeline, "readable_sources", lambda cfg: {**real_readable(cfg), "process": True}
    )
    return queried


def test_request_for_new_source_fetches_it_and_runs_another_round(engine, incident, process_source):
    run(
        incident,
        [
            detection_reply,
            investigation_reply(requests=["process"]),
            investigation_reply(),
            forensics_reply,
            decision_reply("attempted"),
        ],
    )
    assert investigation_rounds(engine) == [1, 2]
    assert process_source  # fetch_more queried it before round 2


def test_evidence_rounds_are_capped(engine, incident, process_source, monkeypatch):
    monkeypatch.setattr(CFG, "MAX_EVIDENCE_ROUNDS", 1)
    run(
        incident,
        [
            detection_reply,
            investigation_reply(requests=["process"]),  # round 1 = cap, request ignored
            forensics_reply,
            decision_reply("attempted"),
        ],
    )
    assert investigation_rounds(engine) == [1]


def test_unknown_evidence_id_fails_the_run(engine, incident):
    bad = json.dumps(
        {
            "attack_type": "rce",
            "hypothesis": "h",
            "indicators": [{"claim": "c", "evidence_ids": ["ev_000000000000"]}],
            "suggested_sources": [],
        }
    )
    with pytest.raises(PipelineFailed) as exc:
        run(incident, [bad, bad])
    assert exc.value.agent == "detection"
    inc = row(engine, "SELECT status, pipeline_state FROM incidents WHERE id = :id", id=incident)
    assert inc["pipeline_state"] == "failed"
    assert inc["status"] == "suspected"  # untouched: only the rules node writes it
    r = row(engine, "SELECT status, error FROM agent_runs")
    assert r["status"] == "invalid"
    assert "ev_000000000000" in r["error"]


def test_bad_citation_then_good_retry_succeeds(engine, incident):
    bad = json.dumps(
        {
            "attack_type": "rce",
            "hypothesis": "h",
            "indicators": [{"claim": "c", "evidence_ids": ["ev_000000000000"]}],
            "suggested_sources": [],
        }
    )
    run(
        incident,
        [bad, detection_reply, investigation_reply(), forensics_reply, decision_reply("attempted")],
    )
    assert row(engine, "SELECT pipeline_state FROM incidents")["pipeline_state"] == "done"


def test_provider_error_fails_the_run(engine, incident):
    with pytest.raises(PipelineFailed):
        run(incident, [TimeoutError("provider timed out")])
    assert row(engine, "SELECT status, error FROM agent_runs")["status"] == "error"
    assert row(engine, "SELECT pipeline_state FROM incidents")["pipeline_state"] == "failed"


def test_refuses_while_running(engine, incident):
    with engine.begin() as conn:
        conn.execute(text("UPDATE incidents SET pipeline_state = 'running'"))
    with pytest.raises(AlreadyRunning):
        run(incident, [])


def test_rerun_replaces_pending_recommendations(engine, incident):
    replies = [detection_reply, investigation_reply(), forensics_reply, decision_reply("attempted")]
    run(incident, replies)
    first = rows(engine, "SELECT id FROM recommendations")
    run(incident, list(replies))
    second = rows(engine, "SELECT id, status FROM recommendations")
    assert len(second) == 1 and second[0]["status"] == "pending"
    assert second[0]["id"] != first[0]["id"]


def test_rerun_keeps_decided_recommendations_and_does_not_repeat_them(engine, incident):
    replies = [detection_reply, investigation_reply(), forensics_reply, decision_reply("attempted")]
    run(incident, replies)
    with engine.begin() as conn:
        conn.execute(text("UPDATE recommendations SET status = 'approved', decided_by = 'test'"))
    run(incident, list(replies))
    statuses = [r["status"] for r in rows(engine, "SELECT status FROM recommendations")]
    assert statuses == ["approved"]
