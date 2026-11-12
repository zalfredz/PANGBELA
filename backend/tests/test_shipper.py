"""shipper/shipper.py: tailing, filtering, batching and retry. Standard library only, so it
is imported from its own folder rather than installed."""

import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shipper"))

import shipper  # noqa: E402

ALERT = {"event_type": "alert", "src_ip": "198.51.100.23"}
FLOW = {"event_type": "flow"}


def line(event) -> str:
    return json.dumps(event) + "\n"


def test_follow_mode_skips_existing_lines(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text(line(ALERT))
    tail = shipper.Tail(str(f), from_start=False)
    assert tail.read_lines() == []
    with f.open("a") as w:
        w.write(line(FLOW))
    assert tail.read_lines() == [line(FLOW).strip()]


def test_from_start_reads_existing_lines(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text(line(ALERT) + line(FLOW))
    assert len(shipper.Tail(str(f), from_start=True).read_lines()) == 2


def test_partial_line_waits_for_its_newline(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text('{"event_type": "al')
    tail = shipper.Tail(str(f), from_start=True)
    assert tail.read_lines() == []
    with f.open("a") as w:
        w.write('ert"}\n')
    assert tail.read_lines() == ['{"event_type": "alert"}']


def test_take_partial_returns_unterminated_last_line(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text(line(FLOW) + json.dumps(ALERT))  # no trailing newline
    tail = shipper.Tail(str(f), from_start=True)
    assert tail.read_lines() + tail.take_partial() == [json.dumps(FLOW), json.dumps(ALERT)]


def test_truncation_restarts_from_beginning(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text(line(FLOW) * 3)
    tail = shipper.Tail(str(f), from_start=True)
    assert len(tail.read_lines()) == 3
    f.write_text(line(ALERT))  # truncated and rewritten, like logrotate copytruncate
    assert tail.read_lines() == [line(ALERT).strip()]


def test_rotation_finishes_old_file_then_reads_new(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text(line(FLOW))
    tail = shipper.Tail(str(f), from_start=True)
    tail.read_lines()
    with f.open("a") as w:
        w.write(line(ALERT))
    f.rename(tmp_path / "eve.json.1")
    f.write_text(line(FLOW))
    assert tail.read_lines() == [line(ALERT).strip(), line(FLOW).strip()]


def test_waits_for_missing_file(tmp_path):
    tail = shipper.Tail(str(tmp_path / "eve.json"), from_start=False)
    assert tail.read_lines() == []


def test_alerts_from_keeps_alerts_only():
    lines = [json.dumps(ALERT), json.dumps(FLOW), "not json", json.dumps([1, 2])]
    assert shipper.alerts_from(lines) == [ALERT]


def test_send_batches_by_100(monkeypatch):
    sizes = []
    monkeypatch.setattr(
        shipper, "post_batch", lambda url, token, b, key: sizes.append(len(b)) or {}
    )
    shipper.send("http://x", "t", [ALERT] * 250)
    assert sizes == [100, 100, 50]


def test_send_retries_until_accepted(monkeypatch):
    attempts, sleeps = [], []

    def flaky(url, token, batch, key):
        attempts.append(1)
        if len(attempts) < 3:
            raise urllib.error.URLError("connection refused")
        return {"accepted": 1}

    monkeypatch.setattr(shipper, "post_batch", flaky)
    shipper.send("http://x", "t", [ALERT], sleep=sleeps.append)
    assert len(attempts) == 3
    assert sleeps == [1.0, 2.0]


def test_send_stops_on_bad_token(monkeypatch):
    def reject(url, token, batch, key):
        raise shipper.FatalIngestError("401")

    monkeypatch.setattr(shipper, "post_batch", reject)
    with pytest.raises(shipper.FatalIngestError):
        shipper.send("http://x", "t", [ALERT])


def test_once_sends_alerts_and_auth_lines_to_their_endpoints(monkeypatch, tmp_path):
    eve, auth = tmp_path / "eve.json", tmp_path / "auth.log"
    eve.write_text(json.dumps(ALERT) + "\n")
    auth.write_text('# comment\n{"a": 1}\n{"b": 2}')  # last line unterminated
    monkeypatch.setenv("EVE_JSON_PATH", str(eve))
    monkeypatch.setenv("INGEST_URL", "http://b/ingest/suricata")
    monkeypatch.setenv("SHIPPER_AUTH_LOG_PATH", str(auth))
    monkeypatch.setenv("AUTH_INGEST_URL", "http://b/ingest/auth")
    monkeypatch.setenv("INGEST_TOKEN", "t")
    posted = []
    monkeypatch.setattr(
        shipper, "post_batch", lambda url, token, b, key: posted.append((url, key, b)) or {}
    )
    assert shipper.main(["--once"]) == 0
    assert posted == [
        ("http://b/ingest/suricata", "events", [ALERT]),
        ("http://b/ingest/auth", "lines", ['{"a": 1}', '{"b": 2}']),
    ]


def test_once_without_token_exits_2(monkeypatch, tmp_path):
    monkeypatch.setenv("EVE_JSON_PATH", str(tmp_path / "eve.json"))
    monkeypatch.delenv("INGEST_TOKEN", raising=False)
    assert shipper.main(["--once"]) == 2
