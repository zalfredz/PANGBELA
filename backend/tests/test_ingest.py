import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import settings
from app.ingest.eve_parser import EveParseError, parse_alert
from app.main import app
from tests.fixtures.eve_alerts import ATTACKER, WEB, alert, flow

TOKEN = "test-token"


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(settings, "INGEST_TOKEN", TOKEN)
    monkeypatch.setattr(settings, "INCIDENT_GROUP_WINDOW_SECONDS", 600)
    return TestClient(app)


def post(client, events, token=TOKEN):
    headers = {"X-Ingest-Token": token} if token is not None else {}
    return client.post("/ingest/suricata", json={"events": events}, headers=headers)


def count(engine, table):
    with engine.connect() as conn:
        return conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()


# --- token ---------------------------------------------------------------------------


def test_bad_token_is_401_and_stores_nothing(client, engine):
    r = post(client, [alert("2026-11-11T02:00:00.000000+0000")], token="wrong")
    assert r.status_code == 401
    assert r.json() == {
        "error": "bad_ingest_token",
        "detail": "X-Ingest-Token is missing or wrong",
    }
    assert count(engine, "alerts") == 0


def test_missing_token_is_401(client):
    r = post(client, [alert("2026-11-11T02:00:00.000000+0000")], token=None)
    assert r.status_code == 401


def test_unconfigured_token_rejects_even_empty_header(engine, monkeypatch):
    monkeypatch.setattr(settings, "INGEST_TOKEN", "")
    r = post(TestClient(app), [], token="")
    assert r.status_code == 503
    assert r.json()["error"] == "ingest_not_configured"


# --- body ----------------------------------------------------------------------------


def test_more_than_100_events_is_422(client):
    r = post(client, [flow("2026-11-11T02:00:00.000000+0000")] * 101)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_request"


def test_non_alert_events_are_ignored(client, engine):
    r = post(
        client,
        [
            flow("2026-11-11T02:00:00.000000+0000"),
            alert("2026-11-11T02:00:01.000000+0000"),
            {"event_type": "http"},
            "not an object",
        ],
    )
    assert r.status_code == 202
    body = r.json()
    assert body["accepted"] == 1
    assert body["ignored"] == 3
    assert len(body["incident_ids"]) == 1
    assert count(engine, "alerts") == 1


def test_malformed_alert_is_ignored_not_fatal(client, engine):
    broken = alert("2026-11-11T02:00:00.000000+0000")
    del broken["src_ip"]
    r = post(client, [broken, alert("2026-11-11T02:00:01.000000+0000")])
    assert r.status_code == 202
    assert r.json()["accepted"] == 1
    assert r.json()["ignored"] == 1


# --- grouping ------------------------------------------------------------------------


def test_alerts_inside_window_share_an_incident(client, engine):
    r = post(
        client,
        [
            alert("2026-11-11T02:00:00.000000+0000"),
            alert("2026-11-11T02:09:00.000000+0000"),  # 540 s later, window is 600
        ],
    )
    assert len(r.json()["incident_ids"]) == 1
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT first_seen, last_seen, status, pipeline_state FROM incidents")
        ).one()
    assert (row.last_seen - row.first_seen).total_seconds() == 540
    assert row.status == "suspected"
    assert row.pipeline_state == "queued"


def test_alert_outside_window_opens_new_incident(client, engine):
    first = post(client, [alert("2026-11-11T02:00:00.000000+0000")]).json()
    later = post(client, [alert("2026-11-11T02:10:01.000000+0000")]).json()  # 601 s
    assert first["incident_ids"] != later["incident_ids"]
    assert count(engine, "incidents") == 2


def test_window_measures_from_last_seen_not_first_seen(client, engine):
    # Each alert is 500 s after the previous one: all inside the window of the
    # incident's latest alert, even though the third is 1000 s after the first.
    for ts in ("02:00:00", "02:08:20", "02:16:40"):
        post(client, [alert(f"2026-11-11T{ts}.000000+0000")])
    assert count(engine, "incidents") == 1


def test_different_ip_pair_opens_new_incident(client, engine):
    r = post(
        client,
        [
            alert("2026-11-11T02:00:00.000000+0000"),
            alert("2026-11-11T02:00:01.000000+0000", src="198.51.100.99"),
        ],
    )
    assert len(r.json()["incident_ids"]) == 2


def test_each_alert_is_stored_as_suricata_evidence(client, engine):
    post(client, [alert("2026-11-11T02:00:00.000000+0000")])
    with engine.connect() as conn:
        ev = conn.execute(
            text(
                "SELECT id, source, host(src_ip) AS ip, summary, fields, collected_by FROM evidence"
            )
        ).one()
    assert ev.id.startswith("ev_")
    assert ev.source == "suricata"
    assert ev.ip == ATTACKER
    assert ev.collected_by == "ingest"
    assert ev.fields["http_url"] == "/ping?host=127.0.0.1;id"
    # Attacker-controlled URL stays out of the code-written summary.
    assert "/ping" not in ev.summary


# --- parser --------------------------------------------------------------------------


def test_parser_converts_timestamp_to_utc():
    a = parse_alert(alert("2026-11-11T09:00:00.000000+0700"))
    assert a.ts.isoformat() == "2026-11-11T02:00:00+00:00"
    assert (a.src_ip, a.dest_ip, a.http_method) == (ATTACKER, WEB, "GET")


@pytest.mark.parametrize("field", ["timestamp", "src_ip", "dest_ip"])
def test_parser_requires_core_fields(field):
    event = alert("2026-11-11T02:00:00.000000+0000")
    del event[field]
    with pytest.raises(EveParseError):
        parse_alert(event)


def test_parser_requires_signature():
    event = alert("2026-11-11T02:00:00.000000+0000")
    del event["alert"]["signature_id"]
    with pytest.raises(EveParseError):
        parse_alert(event)


def test_parser_rejects_naive_timestamp():
    with pytest.raises(EveParseError):
        parse_alert(alert("2026-11-11T02:00:00"))


def test_parser_tolerates_missing_http():
    event = alert("2026-11-11T02:00:00.000000+0000")
    del event["http"]
    assert parse_alert(event).http_url is None
