"""JSON Lines parsers for the access, auth and process logs (docs/log-schema.md)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import Settings
from app.evidence import access_log, auth_log, jsonl, process_log, readable_sources
from app.evidence.redact import redact

FIXTURES = Path(__file__).parent / "fixtures"
ACCESS = str(FIXTURES / "access_rce.jsonl")
AUTH = str(FIXTURES / "auth_burst.jsonl")
PROCESS = str(FIXTURES / "process_rce.jsonl")
INCIDENT = uuid4()


def line(**fields) -> str:
    return json.dumps(fields)


# --- access log -----------------------------------------------------------------------


def test_access_line_splits_query_and_keeps_raw():
    raw = line(
        timestamp="2026-11-11T09:00:00+07:00",
        request_id="r-1",
        src_ip="198.51.100.23",
        method="GET",
        path="/ping?host=1;id",
        status=200,
        user_agent="curl/8.7.1",
        service="web-lab",
    )
    ev = access_log.parse_line(raw, INCIDENT)
    assert ev is not None
    assert ev.ts == datetime(2026, 11, 11, 2, 0, tzinfo=UTC)
    assert (ev.source, ev.src_ip, ev.raw) == ("access_log", "198.51.100.23", raw)
    assert ev.fields == {
        "request_id": "r-1",
        "method": "GET",
        "path": "/ping",
        "query": "host=1;id",
        "status": 200,
        "user_agent": "curl/8.7.1",
        "service": "web-lab",
        "policy": None,
    }


def test_numeric_request_id_becomes_text():
    raw = line(
        timestamp="2026-11-11T02:00:00Z",
        request_id=7,
        src_ip="198.51.100.23",
        method="GET",
        path="/",
        status=200,
    )
    assert access_log.parse_line(raw, INCIDENT).fields["request_id"] == "7"


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[1, 2]",
        line(src_ip="198.51.100.23", method="GET", path="/", status=200),
        line(timestamp="2026-11-11T02:00:00", src_ip="1.2.3.4", method="GET", path="/", status=1),
        line(timestamp="2026-11-11T02:00:00Z", src_ip="nope", method="GET", path="/", status=200),
        line(timestamp="2026-11-11T02:00:00Z", src_ip="1.2.3.4", method="GET", path="/"),
        line(timestamp="2026-11-11T02:00:00Z", src_ip="1.2.3.4", path="/", status=200),
        line(timestamp="2026-11-11T02:00:00Z", src_ip="1.2.3.4", method="GET", status=200),
        line(
            timestamp="2026-11-11T02:00:00Z", src_ip="1.2.3.4", method="GET", path="/", status=True
        ),
    ],
)
def test_access_invalid_lines_rejected(raw):
    assert access_log.parse_line(raw, INCIDENT) is None


def test_access_summary_truncates_attacker_path():
    raw = line(
        timestamp="2026-11-11T02:00:00Z",
        src_ip="198.51.100.23",
        method="GET",
        path="/" + "a" * 500,
        status=404,
    )
    assert len(access_log.parse_line(raw, INCIDENT).summary) < 140


def test_access_query_filters_by_ip_and_time_and_skips_bad_lines():
    start = datetime(2026, 11, 11, 1, 59, 0, tzinfo=UTC)
    end = datetime(2026, 11, 11, 2, 0, 5, tzinfo=UTC)
    events = access_log.query(ACCESS, "198.51.100.23", start, end, INCIDENT)
    assert [e.fields["request_id"] for e in events] == ["fx-req-0001", "fx-req-0002"]
    assert events[1].fields["query"] == "host=127.0.0.1;id"


# --- auth log -------------------------------------------------------------------------


def test_auth_line():
    raw = line(
        timestamp="2026-11-11T03:00:00Z",
        event_type="login",
        username="admin",
        src_ip="198.51.100.40",
        result="failure",
        service="auth-service",
    )
    ev = auth_log.parse_line(raw, INCIDENT)
    assert (ev.source, ev.src_ip, ev.raw) == ("auth_log", "198.51.100.40", raw)
    assert ev.fields == {
        "event_type": "login",
        "username": "admin",
        "result": "failure",
        "service": "auth-service",
        "request_id": None,
        "authorized": None,
    }
    assert ev.summary == "Login failure for user admin on auth-service from 198.51.100.40"


@pytest.mark.parametrize(("value", "expected"), [(False, False), (True, True), ("false", None)])
def test_auth_authorized_must_be_a_boolean(value, expected):
    raw = line(
        timestamp="2026-11-11T03:00:00Z", src_ip="198.51.100.40", result="success", authorized=value
    )
    assert auth_log.parse_line(raw, INCIDENT).fields["authorized"] is expected


@pytest.mark.parametrize("result", ["locked", "FAILURE", None])
def test_auth_result_must_be_success_or_failure(result):
    raw = line(timestamp="2026-11-11T03:00:00Z", src_ip="198.51.100.40", result=result)
    assert auth_log.parse_line(raw, INCIDENT) is None


def test_auth_query_by_ip():
    start = datetime(2026, 11, 11, 3, 0, tzinfo=UTC)
    end = datetime(2026, 11, 11, 3, 5, tzinfo=UTC)
    events = auth_log.query(AUTH, "198.51.100.40", start, end, INCIDENT)
    assert len(events) == 13
    assert [e.fields["result"] for e in events].count("success") == 1
    others = auth_log.query(AUTH, "192.0.2.60", start, end, INCIDENT)
    assert len(others) == 3  # the "locked" line is skipped


# --- process log ----------------------------------------------------------------------


def test_process_line_and_summary_without_cmdline():
    start = datetime(2026, 11, 11, 2, 0, tzinfo=UTC)
    end = datetime(2026, 11, 11, 2, 1, tzinfo=UTC)
    events = process_log.query(PROCESS, "ignored", start, end, INCIDENT)
    assert len(events) == 2  # the line without pid is skipped
    sh = events[0]
    assert sh.src_ip is None
    assert sh.fields["request_id"] == "fx-req-0002"
    assert sh.fields["uid"] == "33"
    assert sh.fields["parent_exe"] == "/usr/local/bin/gunicorn"
    assert ";id" not in sh.summary  # the command line stays in raw and fields
    assert sh.summary == "Process sh pid 4242 started by gunicorn ppid 17 uid 33 on 0123456789ab"


def test_process_query_is_by_time_only():
    start = datetime(2026, 11, 11, 2, 0, 1, tzinfo=UTC)
    end = datetime(2026, 11, 11, 2, 1, tzinfo=UTC)
    events = process_log.query(PROCESS, "198.51.100.23", start, end, INCIDENT)
    assert [e.fields["pid"] for e in events] == [4250]


# --- availability ---------------------------------------------------------------------


def test_readable_sources_follow_the_files():
    cfg = Settings(ACCESS_LOG_PATH=ACCESS, AUTH_LOG_PATH="/nonexistent", PROCESS_LOG_PATH=PROCESS)
    assert readable_sources(cfg) == {"access_log": True, "auth_log": False, "process": True}


def test_line_error_is_a_value_error():
    with pytest.raises(ValueError):
        jsonl.load("nope")


# --- redaction before the LLM ---------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "/login?user=admin&password=hunter2&next=/",
            "/login?user=admin&password=[REDACTED]&next=/",
        ),
        ('{"username": "a", "passwd": "x y"}', '{"username": "a", "passwd": "[REDACTED]"}'),
        ("Authorization: Bearer abc.def.ghi", "Authorization: [REDACTED] [REDACTED]"),
        ("curl https://bob:s3cret@lab.test/x", "curl https://bob:[REDACTED]@lab.test/x"),
        ("api_key=K1; session=abc", "api_key=[REDACTED]; session=[REDACTED]"),
        ("TOKEN: zzz", "TOKEN: [REDACTED]"),
    ],
)
def test_redact(text, expected):
    assert redact(text) == expected


def test_redact_keeps_attack_payload_and_unrelated_keys():
    text = "/ping?host=127.0.0.1;cat%20/etc/passwd&passwords_seen=3"
    assert redact(text) == text
