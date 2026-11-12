"""Deliberately vulnerable lab web app. Every process event is read from /proc of a
child this process really started; only the harmless marker may be executed."""

import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOG_DIR = os.environ.get("LAB_LOG_DIR", "/lab-logs")
PROCESS_LOG = os.environ.get("PROCESS_LOG_DISABLED") != "1"
SERVICE = "lab-web"
MARKER = "LAB_RCE_OK"
SAFE_HOST = re.compile(r"^[A-Za-z0-9.\-]{1,64}$")
# The only command that may run after the separator. Anything else is refused before
# exec, so the lab never executes attacker-chosen commands.
INJECTION = re.compile(r"^127\.0\.0\.1;\s*printf " + MARKER + r"\s*$")
APPROVAL_SECRET = os.environ.get("LAB_APPROVAL_SECRET", "")
_APPROVAL_WINDOW_SECONDS = 120
_seen_nonces: dict[str, float] = {}
_lock = threading.Lock()


def approval_ok(path: str, header: str | None) -> bool:
    """A signed, unexpired, never-seen approval for exactly this path. A copied header
    is rejected because each nonce is accepted once."""
    if not APPROVAL_SECRET or not header:
        return False
    try:
        ts, nonce, mac = header.split(":", 2)
        if abs(time.time() - int(ts)) > _APPROVAL_WINDOW_SECONDS:
            return False
    except ValueError:
        return False
    expected = hmac.new(
        APPROVAL_SECRET.encode(), f"{ts}:{nonce}:{path}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return False
    with _lock:
        if nonce in _seen_nonces:
            return False
        _seen_nonces[nonce] = time.time()
        for old in [n for n, at in _seen_nonces.items() if at < time.time() - 600]:
            _seen_nonces.pop(old, None)
    return True


def now() -> str:
    return datetime.now(UTC).isoformat()


def write(name: str, event: dict) -> None:
    line = json.dumps(event) + "\n"
    with _lock, open(os.path.join(LOG_DIR, name), "a", encoding="utf-8") as f:
        f.write(line)


def exe_of(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def run_child(argv: list[str], request_id: str, authorized: bool) -> tuple[int, str]:
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    parent = os.getpid()
    # /proc/<pid>/exe is briefly unset between fork and exec; the lab children sleep
    # 200 ms first so the read below always sees the real executable.
    exe = exe_of(child.pid)
    # pid/ppid/exe are read from /proc while the child exists: observed, not invented.
    event = {
        "timestamp": now(),
        "host": socket.gethostname(),
        "container_id": os.environ.get("HOSTNAME"),
        "pid": child.pid,
        "ppid": parent,
        "exe": exe or "unknown",
        "parent_exe": exe_of(parent),
        "cmdline": " ".join(argv),
        "uid": str(os.getuid()),
        "request_id": request_id,
        "authorized": authorized,
    }
    if PROCESS_LOG:
        write("process.log", event)
    try:
        out, _ = child.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        out, _ = child.communicate()
    return child.returncode, out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # access logging is the JSONL file below
        pass

    def do_GET(self) -> None:
        request_id = uuid.uuid4().hex
        url = urlparse(self.path)
        host = parse_qs(url.query).get("host", [""])[0]
        approval_header = self.headers.get("X-Lab-Approval")
        approved = approval_ok(self.path, approval_header)
        status, body = 404, "not found"

        if url.path == "/healthz":
            status, body = 200, "ok"
        elif approval_header and not approved:
            # A forged or replayed approval is refused before anything runs.
            status, body = 400, "refused: invalid or replayed approval"
        elif url.path in ("/vuln/ping", "/safe/ping"):
            status, body = self.handle_ping(
                host, request_id, vuln=url.path == "/vuln/ping", approved=approved
            )

        write(
            "access.log",
            {
                "timestamp": now(),
                "request_id": request_id,
                "src_ip": self.client_address[0],
                "method": "GET",
                "path": self.path,
                "status": status,
                "user_agent": self.headers.get("User-Agent", ""),
                "service": SERVICE,
                # approved = signature verified by this app, never a client-supplied label.
                "policy": "approved" if approved else "untrusted",
            },
        )
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_ping(
        self, host: str, request_id: str, vuln: bool, approved: bool
    ) -> tuple[int, str]:
        if SAFE_HOST.match(host):
            # Sanitized input: no shell, and the policy allows this child.
            code, _ = run_child(["/bin/sleep", "0.2"], request_id, authorized=True)
            return (200 if code == 0 else 500), f"ok {host}"
        if vuln and INJECTION.match(host) and approved:
            # v1_sanitize_ping: the shell is gone. Only a signed maintenance request
            # may run the marker, through a fixed argv with no attacker-controlled text.
            code, out = run_child(["/usr/bin/printf", MARKER], request_id, authorized=True)
            return (200 if code == 0 else 500), out
        return 400, "refused: payload not in the lab allowlist"


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
