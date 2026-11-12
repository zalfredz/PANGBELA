"""Authentication ingest is a separate trust domain from Suricata ingest: its producer
can state whether a login was authorized, so the two tokens must not be interchangeable."""

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import settings
from app.main import app

TOKEN = "auth-test-token"
ALERT_TOKEN = "suricata-test-token"
SRC = "198.51.100.50"


def line(result: str = "failure", **extra) -> str:
    obj = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "login",
        "username": "victim",
        "src_ip": SRC,
        "result": result,
        "service": "lab-auth",
        **extra,
    }
    return json.dumps(obj)


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_INGEST_TOKEN", TOKEN)
    monkeypatch.setattr(settings, "INGEST_TOKEN", ALERT_TOKEN)
    monkeypatch.setattr(settings, "AUTH_INGEST_PRODUCER", "lab-auth-test")
    return TestClient(app)


def post(lines: list[str], token: str | None = TOKEN, header: str = "X-Auth-Ingest-Token"):
    headers = {header: token} if token is not None else {}
    return TestClient(app).post("/ingest/auth", json={"lines": lines}, headers=headers)


def test_suricata_token_cannot_write_login_events(client):
    r = post([line()], token=ALERT_TOKEN)
    assert r.status_code == 401
    assert r.json()["error"] == "bad_auth_ingest_token"


def test_auth_token_cannot_write_network_alerts(client):
    r = TestClient(app).post(
        "/ingest/suricata", json={"events": []}, headers={"X-Ingest-Token": TOKEN}
    )
    assert r.status_code == 401
    assert r.json()["error"] == "bad_ingest_token"


def test_missing_auth_token_is_401(client):
    assert post([line()], token=None).status_code == 401


def test_auth_ingest_fails_closed_when_unconfigured(engine, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_INGEST_TOKEN", "")
    r = post([line()], token="")
    assert r.status_code == 503
    assert r.json()["error"] == "auth_ingest_not_configured"


def test_producer_is_recorded(client, engine):
    assert post([line()]).status_code == 202
    with engine.connect() as conn:
        producer = conn.execute(text("SELECT producer FROM auth_events")).scalar_one()
    assert producer == "lab-auth-test"


def test_malformed_lines_are_ignored_not_stored(client, engine):
    r = post(["not json", json.dumps({"timestamp": "nope"}), line()])
    assert r.status_code == 202
    assert (r.json()["accepted"], r.json()["ignored"]) == (1, 2)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM auth_events")).scalar_one() == 1


def test_authorized_must_be_a_json_boolean(client, engine):
    # A string "false" must not become a trusted unauthorized-login fact.
    assert post([line("success", authorized="false")]).status_code == 202
    with engine.connect() as conn:
        stored = conn.execute(text("SELECT fields->>'authorized' FROM auth_events")).scalar_one()
    assert stored is None
