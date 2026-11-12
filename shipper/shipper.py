"""Tail Suricata's eve.json (and optionally the lab auth log) and post to the backend.

    python shipper.py               follow the file from its current end, like tail -f
    python shipper.py --from-start  read the whole file first, then follow it
    python shipper.py --once        read the whole file, post it, and exit (replaying samples/)

Env: EVE_JSON_PATH, INGEST_URL, INGEST_TOKEN, and optionally SHIPPER_AUTH_LOG_PATH
with AUTH_INGEST_URL (spec sections 3 and 8). Standard library only.

Only complete lines are sent: Suricata may be mid-write on the last one. A batch is
retried until the backend accepts it, so nothing is dropped while the backend is down.
The read position is not saved: after a restart without --from-start, alerts written
while the shipper was down are not sent.
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request

BATCH_SIZE = 100  # the ingest endpoint's limit
IDLE_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0

log = logging.getLogger("shipper")


class FatalIngestError(Exception):
    """The backend rejected us in a way retrying won't fix (bad token)."""


class Tail:
    """Reads complete new lines from a file, reopening it after rotation or truncation."""

    def __init__(self, path: str, from_start: bool):
        self.path = path
        self._file = None
        self._inode: int | None = None
        self._partial = ""
        self._from_start = from_start

    def _open(self) -> bool:
        try:
            f = open(self.path, encoding="utf-8", errors="replace")  # noqa: SIM115 - kept open
        except FileNotFoundError:
            return False
        st = os.fstat(f.fileno())
        if not self._from_start and self._inode is None:
            f.seek(0, os.SEEK_END)  # first open in follow mode: skip what is already there
        self._file, self._inode, self._partial = f, st.st_ino, ""
        return True

    def read_lines(self) -> list[str]:
        if self._file is None and not self._open():
            return []
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            st = None
        rotated = st is not None and st.st_ino != self._inode
        truncated = st is not None and st.st_size < self._file.tell()
        lines = self._drain()
        if rotated or truncated:
            # Finish the old file first (done above), then start the new one from 0.
            self._file.close()
            self._file, self._from_start = None, True
            if self._open():
                lines += self._drain()
        return lines

    def _drain(self) -> list[str]:
        data = self._partial + self._file.read()
        *complete, self._partial = data.split("\n")
        return [line for line in complete if line.strip()]

    def take_partial(self) -> list[str]:
        """The unterminated last line. Only for --once, where the file is finished: in
        follow mode it may be a line Suricata is still writing."""
        rest, self._partial = self._partial, ""
        return [rest] if rest.strip() else []

    def close(self) -> None:
        if self._file is not None:
            self._file.close()


def alerts_from(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            log.warning("skipped a line that is not JSON (%d chars)", len(line))
            continue
        # The backend ignores other event types anyway; filtering here saves traffic.
        if isinstance(event, dict) and event.get("event_type") == "alert":
            out.append(event)
    return out


def auth_lines_from(lines: list[str]) -> list[str]:
    # Sent as raw lines: the backend validates them and keeps each line unchanged.
    return [line for line in lines if not line.startswith("#")]


def post_batch(
    url: str, token: str, events: list, key: str = "events", timeout: float = 10.0
) -> dict:
    """POST one batch as {key: events}. Raises FatalIngestError on 401, urllib errors on
    anything retryable."""
    body = json.dumps({key: events}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Ingest-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise FatalIngestError("backend rejected INGEST_TOKEN (401)") from e
        if e.code == 422:
            # The batch itself is malformed; resending it would loop forever.
            log.error("backend rejected a batch of %d events (422), dropping it", len(events))
            return {"accepted": 0, "ignored": len(events), "incident_ids": []}
        raise


def send(url: str, token: str, events: list, sleep=time.sleep, key: str = "events") -> None:
    """Send events in batches, retrying each batch with backoff until it is accepted."""
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i : i + BATCH_SIZE]
        delay = 1.0
        while True:
            try:
                result = post_batch(url, token, batch, key)
                log.info(
                    "posted %d %s: accepted=%s ignored=%s incidents=%s",
                    len(batch),
                    "alerts" if key == "events" else "auth lines",
                    result.get("accepted"),
                    result.get("ignored"),
                    result.get("incident_ids"),
                )
                break
            except FatalIngestError:
                raise
            except (urllib.error.URLError, OSError, ValueError) as e:
                log.warning("post failed (%s), retrying in %.0f s", e, delay)
                sleep(delay)
                delay = min(delay * 2, MAX_BACKOFF_SECONDS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--from-start", action="store_true")
    mode.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # `or`: .env.example ships these blank, and blank means "use the default".
    path = os.environ.get("EVE_JSON_PATH") or "/var/log/suricata/eve.json"
    url = os.environ.get("INGEST_URL") or "http://backend:8000/ingest/suricata"
    token = os.environ.get("INGEST_TOKEN") or ""
    if not token:
        log.error("INGEST_TOKEN is not set")
        return 2

    # Optional: the lab's auth log, so brute force opens an incident even without a
    # Suricata alert. Unset = Suricata only.
    auth_path = os.environ.get("SHIPPER_AUTH_LOG_PATH") or ""
    auth_url = os.environ.get("AUTH_INGEST_URL") or "http://backend:8000/ingest/auth"

    from_start = args.from_start or args.once
    tail = Tail(path, from_start=from_start)
    auth_tail = Tail(auth_path, from_start=from_start) if auth_path else None
    try:
        if args.once:
            for p in [path] + ([auth_path] if auth_path else []):
                if not os.path.exists(p):
                    log.error("%s does not exist", p)
                    return 2
            send(url, token, alerts_from(tail.read_lines() + tail.take_partial()))
            if auth_tail:
                lines = auth_lines_from(auth_tail.read_lines() + auth_tail.take_partial())
                send(auth_url, token, lines, key="lines")
            return 0
        log.info("following %s%s", path, f" and {auth_path}" if auth_path else "")
        while True:
            alerts = alerts_from(tail.read_lines())
            auth_lines = auth_lines_from(auth_tail.read_lines()) if auth_tail else []
            if alerts:
                send(url, token, alerts)
            if auth_lines:
                send(auth_url, token, auth_lines, key="lines")
            if not alerts and not auth_lines:
                time.sleep(IDLE_SECONDS)
    except FatalIngestError as e:
        log.error("%s", e)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        tail.close()
        if auth_tail:
            auth_tail.close()


if __name__ == "__main__":
    sys.exit(main())
