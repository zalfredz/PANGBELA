"""Start-delay loop: which incidents start, when, and recovery after a restart."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.ingest.eve_parser import parse_alert
from app.ingest.grouping import group_alert
from app.llm.client import LLMClient
from app.runner import Runner, recover_stale_runs
from tests.fake_llm import FakeSDK
from tests.fixtures.eve_alerts import alert
from tests.test_pipeline import (
    CFG,
    decision_reply,
    detection_reply,
    forensics_reply,
    investigation_reply,
)

RUN_CFG = CFG.model_copy(
    update={"LLM_BASE_URL": "http://fake", "LLM_API_KEY": "x", "PIPELINE_DEBOUNCE_SECONDS": 30}
)


def replies():
    return [detection_reply, investigation_reply(), forensics_reply, decision_reply("attempted")]


@pytest.fixture
def runner(engine):
    r = Runner(RUN_CFG, client_factory=lambda: LLMClient(RUN_CFG, sdk=FakeSDK(replies())))
    yield r
    r.shutdown()


def incident_seen(engine, seconds_ago: float, src="198.51.100.23"):
    ts = (datetime.now(UTC) - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    with engine.begin() as conn:
        incident_id, _ = group_alert(conn, parse_alert(alert(ts, src=src)), 600)
    return incident_id


def state(engine, incident_id) -> str:
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT pipeline_state FROM incidents WHERE id = :id"), {"id": incident_id}
        ).scalar_one()


def test_starts_incident_after_debounce(engine, runner):
    incident_id = incident_seen(engine, seconds_ago=31)
    future = runner.tick()
    assert future is not None
    future.result(timeout=30)
    assert state(engine, incident_id) == "done"


def test_waits_while_alerts_are_recent(engine, runner):
    incident_id = incident_seen(engine, seconds_ago=5)
    assert runner.tick() is None
    assert state(engine, incident_id) == "queued"


def test_ignores_incidents_that_are_not_queued(engine, runner):
    incident_id = incident_seen(engine, seconds_ago=60)
    with engine.begin() as conn:
        conn.execute(text("UPDATE incidents SET pipeline_state = 'done'"))
    assert runner.tick() is None
    assert state(engine, incident_id) == "done"


def test_one_pipeline_at_a_time_oldest_first(engine, runner):
    older = incident_seen(engine, seconds_ago=90, src="198.51.100.1")
    newer = incident_seen(engine, seconds_ago=60, src="198.51.100.2")
    first = runner.tick()
    first.result(timeout=30)
    assert (state(engine, older), state(engine, newer)) == ("done", "queued")
    runner.tick().result(timeout=30)
    assert state(engine, newer) == "done"


def test_does_nothing_without_llm_config(engine):
    cfg = RUN_CFG.model_copy(update={"LLM_API_KEY": ""})
    r = Runner(cfg)
    incident_id = incident_seen(engine, seconds_ago=60)
    assert r.tick() is None
    assert state(engine, incident_id) == "queued"
    r.shutdown()


def test_failed_run_frees_the_runner(engine):
    bad = Runner(RUN_CFG, client_factory=lambda: LLMClient(RUN_CFG, sdk=FakeSDK(["x", "y"])))
    first = incident_seen(engine, seconds_ago=90, src="198.51.100.1")
    bad.tick().result(timeout=30)
    assert state(engine, first) == "failed"
    second = incident_seen(engine, seconds_ago=60, src="198.51.100.2")
    future = bad.tick()
    assert future is not None  # not stuck busy after the failure
    future.result(timeout=30)
    assert state(engine, second) == "failed"
    bad.shutdown()


def test_recover_stale_runs_marks_running_failed(engine):
    incident_id = incident_seen(engine, seconds_ago=60)
    with engine.begin() as conn:
        conn.execute(text("UPDATE incidents SET pipeline_state = 'running'"))
    assert recover_stale_runs() == 1
    assert state(engine, incident_id) == "failed"
