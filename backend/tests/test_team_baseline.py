"""Team baseline of 11 Nov 2026: brute force opened from auth log events, attack type
set by code, early warnings, and redaction before the LLM."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text

from app.agents.base import format_evidence
from app.api.incidents import replay_events
from app.config import Settings, settings
from app.events import broker
from app.evidence.store import EvidenceEvent
from app.graph.pipeline import claim_incident, run_pipeline
from app.ingest.eve_parser import parse_alert
from app.ingest.grouping import group_alert
from app.llm.client import LLMClient
from app.main import app
from app.runner import Runner
from tests.fake_llm import FakeSDK
from tests.fixtures.eve_alerts import alert
from tests.test_pipeline import (
    CFG,
    decision_reply,
    detection_reply,
    forensics_reply,
    investigation_reply,
)

FIXTURES = Path(__file__).parent / "fixtures"
AUTH = FIXTURES / "auth_burst.jsonl"
TOKEN = "test-token"
BURST_IP = "198.51.100.40"


def auth_lines(ip: str | None = None) -> list[str]:
    lines = [
        line for line in AUTH.read_text().splitlines() if line.strip() and not line.startswith("#")
    ]
    return [line for line in lines if ip is None or f'"{ip}"' in line]


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(settings, "INGEST_TOKEN", TOKEN)
    monkeypatch.setattr(settings, "BRUTE_FORCE_MIN_FAILURES", 10)
    monkeypatch.setattr(settings, "BRUTE_FORCE_WINDOW_SECONDS", 120)
    monkeypatch.setattr(settings, "INCIDENT_GROUP_WINDOW_SECONDS", 600)
    return TestClient(app)


def post_auth(client, lines, token=TOKEN):
    return client.post("/ingest/auth", json={"lines": lines}, headers={"X-Ingest-Token": token})


def scalar(engine, sql, **params):
    with engine.connect() as conn:
        return conn.execute(text(sql), params).scalar()


def incidents(engine):
    with engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT id, host(src_ip) AS src_ip, dest_ip, attack_type, opened_by,"
                    " first_seen, last_seen FROM incidents"
                )
            )
            .mappings()
            .all()
        )


# --- POST /ingest/auth ----------------------------------------------------------------


def test_auth_ingest_needs_the_token(client, engine):
    assert post_auth(client, auth_lines(), token="wrong").status_code == 401
    assert scalar(engine, "SELECT count(*) FROM auth_events") == 0


def test_burst_opens_brute_force_incident_with_its_login_events(client, engine):
    r = post_auth(client, auth_lines())
    assert r.status_code == 202
    body = r.json()
    assert (body["accepted"], body["ignored"]) == (16, 1)  # the "locked" line is invalid
    [inc] = incidents(engine)
    assert body["incident_ids"] == [str(inc["id"])]
    assert (inc["src_ip"], inc["dest_ip"], inc["attack_type"], inc["opened_by"]) == (
        BURST_IP,
        None,
        "brute_force",
        "auth_log",
    )
    assert inc["first_seen"] == datetime(2026, 11, 11, 3, 0, tzinfo=UTC)
    assert inc["last_seen"] == datetime(2026, 11, 11, 3, 1, tzinfo=UTC)
    # 12 failures and the success, stored as auth_log evidence; 192.0.2.60 opened nothing.
    assert scalar(engine, "SELECT count(*) FROM evidence WHERE source = 'auth_log'") == 13


def test_resent_lines_are_not_counted_twice(client, engine):
    post_auth(client, auth_lines(BURST_IP))
    r = post_auth(client, auth_lines(BURST_IP))
    assert r.json()["incident_ids"] == []  # nothing new stored, so nothing touched
    assert scalar(engine, "SELECT count(*) FROM auth_events") == 13
    assert scalar(engine, "SELECT count(*) FROM evidence") == 13
    assert len(incidents(engine)) == 1


def test_threshold_counts_across_batches(client, engine):
    lines = auth_lines(BURST_IP)
    assert post_auth(client, lines[:6]).json()["incident_ids"] == []
    assert len(incidents(engine)) == 0
    assert len(post_auth(client, lines[6:]).json()["incident_ids"]) == 1
    assert scalar(engine, "SELECT count(*) FROM evidence") == 13


def test_normal_password_mistakes_open_nothing(client, engine):
    r = post_auth(client, auth_lines("192.0.2.60"))
    assert r.json()["incident_ids"] == []
    assert incidents(engine) == []


# --- attack type set by code ----------------------------------------------------------


def test_lab_signature_id_sets_attack_type_at_ingest(engine):
    cfg = Settings(RCE_SIGNATURE_IDS="2100498")
    with engine.begin() as conn:
        incident_id, _ = group_alert(
            conn,
            parse_alert(alert("2026-11-11T02:00:00.000000+0000")),
            600,
            cfg.signature_attack_types,
        )
    assert scalar(engine, "SELECT attack_type FROM incidents WHERE id = :id", id=incident_id) == (
        "rce"
    )
    assert claim_incident(incident_id, cfg=cfg).attack_type == "rce"


def test_agent_type_from_an_earlier_run_is_not_treated_as_code_type(engine):
    with engine.begin() as conn:
        incident_id, _ = group_alert(
            conn, parse_alert(alert("2026-11-11T02:00:00.000000+0000")), 600
        )
        conn.execute(text("UPDATE incidents SET attack_type = 'rce'"))
    assert claim_incident(incident_id, cfg=Settings()).attack_type == "unknown"


@pytest.mark.parametrize(
    ("rce", "bf", "error"),
    [("12,abc", "", "not a signature id"), ("1,2", "2", "listed as rce and brute_force")],
)
def test_signature_id_settings_are_checked_at_startup(rce, bf, error):
    with pytest.raises(ValidationError, match=error):
        Settings(RCE_SIGNATURE_IDS=rce, BRUTE_FORCE_SIGNATURE_IDS=bf)


def test_auth_opened_incident_keeps_brute_force_and_confirms_on_unauthorized_login(client, engine):
    post_auth(client, auth_lines(BURST_IP))
    [inc] = incidents(engine)
    cfg = CFG.model_copy(update={"AUTH_LOG_PATH": str(AUTH)})
    replies = [detection_reply, investigation_reply(), forensics_reply, decision_reply("attempted")]
    sdk = FakeSDK(replies)
    run_pipeline(inc["id"], LLMClient(cfg, sdk=sdk), cfg)

    # The detection agent saw the login events, not Suricata alerts.
    assert "Login failure for user admin" in sdk.calls[0]["messages"][1]["content"]
    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT attack_type, status, severity, verification_state, confidence_level"
                    " FROM incidents"
                )
            )
            .mappings()
            .one()
        )
        rules = conn.execute(
            text("SELECT output_json, rules_conflict FROM agent_runs WHERE agent = 'rules'")
        ).one()
    # The fake detection answers "rce"; code's brute_force stands.
    assert dict(row) == {
        "attack_type": "brute_force",
        "status": "confirmed",
        "severity": "high",
        "verification_state": "verified",
        "confidence_level": "medium",  # the decision proposed attempted: a conflict
    }
    assert rules.output_json["detection_attack_type"] == "rce"
    assert rules.rules_conflict == "proposed attempted, rules allow confirmed"


# --- early warning --------------------------------------------------------------------


@pytest.fixture
def emitted(monkeypatch):
    out = []
    monkeypatch.setattr(broker, "emit", lambda incident_id, e: out.append((incident_id, e)))
    return out


def test_assess_warns_once_for_a_provisional_high(client, engine, emitted):
    post_auth(client, auth_lines(BURST_IP))
    [inc] = incidents(engine)
    emitted.clear()
    cfg = CFG.model_copy(update={"AUTH_LOG_PATH": str(AUTH)})
    runner = Runner(cfg)
    try:
        assert runner.assess() == 1
        warnings = [e for _, e in emitted if e.name == "early_warning"]
        assert [w.data for w in warnings] == [
            {
                "status": "confirmed",
                "severity": "high",
                "verification_state": "verified",
                "provisional": True,
            }
        ]
        assert runner.assess() == 0  # unchanged: no second warning
    finally:
        runner.shutdown()
    with engine.connect() as conn:
        replay = replay_events(conn, inc["id"])
    assert [e.key for e in replay if e.name == "early_warning"] == [warnings[0].key]


def test_assess_skips_incidents_without_a_code_type(engine, emitted):
    with engine.begin() as conn:
        group_alert(conn, parse_alert(alert("2026-11-11T02:00:00.000000+0000")), 600)
    runner = Runner(CFG)
    try:
        assert runner.assess() == 0
    finally:
        runner.shutdown()
    assert scalar(engine, "SELECT provisional_status FROM incidents") is None


def test_assess_runs_without_llm_configured(client, engine, emitted):
    post_auth(client, auth_lines(BURST_IP))
    cfg = Settings(AUTH_LOG_PATH=str(AUTH), LLM_BASE_URL="", LLM_API_KEY="", LLM_MODEL="")
    assert not cfg.llm_configured
    runner = Runner(cfg)
    try:
        assert runner.assess() == 1
    finally:
        runner.shutdown()


# --- redaction ------------------------------------------------------------------------


def test_llm_sees_redacted_evidence_but_database_keeps_raw():
    raw = '{"path": "/login?user=a&password=hunter2"}'
    ev = EvidenceEvent(
        incident_id=uuid4(),
        source="access_log",
        ts=datetime(2026, 11, 11, tzinfo=UTC),
        src_ip="198.51.100.23",
        summary="s",
        raw=raw,
        fields={},
    )
    shown = format_evidence([ev])
    assert "hunter2" not in shown
    assert "password=[REDACTED]" in shown
    assert ev.raw == raw
