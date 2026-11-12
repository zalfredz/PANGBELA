"""Lab authentication service with synthetic accounts.

Whether a successful login is authorized comes from this service's own policy (the
client's source address against the account's allowed CIDRs), never from the request.
Each event is written to auth.log and posted to the backend's auth ingest endpoint, the
same one the shipper uses."""

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network

LOG_DIR = os.environ.get("LAB_LOG_DIR", "/lab-logs")
INGEST_URL = os.environ.get("AUTH_INGEST_URL", "http://backend:8000/ingest/auth")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")
SERVICE = "lab-auth"

# Passwords are synthetic lab values. Allowed CIDRs are the authority: an analyst may
# log in from the lab subnet, the victim account only from localhost (never in the lab).
USERS = {
    "analyst": {"password": "lab-analyst", "allowed": ["172.28.0.0/16"]},
    "victim": {"password": "lab-victim", "allowed": ["127.0.0.1/32"]},
}


def now() -> str:
    return datetime.now(UTC).isoformat()


def authorized_for(username: str, src_ip: str) -> bool:
    allowed = USERS.get(username, {}).get("allowed", [])
    return any(ip_address(src_ip) in ip_network(cidr) for cidr in allowed)


def emit(event: dict) -> None:
    line = json.dumps(event)
    with open(os.path.join(LOG_DIR, "auth.log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")
    if not INGEST_TOKEN:
        return
    for attempt in range(3):
        req = urllib.request.Request(
            INGEST_URL,
            data=json.dumps({"lines": [line]}).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "X-Ingest-Token": INGEST_TOKEN},
        )
        try:
            with urllib.request.urlopen(req, timeout=5):
                return
        except (urllib.error.URLError, OSError):
            time.sleep(1 + attempt)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            body = {}
        username = str(body.get("username", ""))[:64]
        password = str(body.get("password", ""))
        src_ip = self.client_address[0]
        ok = username in USERS and USERS[username]["password"] == password
        event = {
            "timestamp": now(),
            "event_type": "login",
            "username": username,
            "src_ip": src_ip,
            "result": "success" if ok else "failure",
            "service": SERVICE,
            "request_id": uuid.uuid4().hex,
        }
        if ok:
            event["authorized"] = authorized_for(username, src_ip)
        emit(event)
        payload = json.dumps({"ok": ok}).encode()
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
