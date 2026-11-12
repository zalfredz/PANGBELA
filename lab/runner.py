"""Scenario runner. One scenario per invocation so incidents never merge across
scenarios; the integration script resets the database between runs."""

import json
import os
import sys
import time
import urllib.error
import urllib.request

APP = "http://app:8080"
AUTH = "http://auth:8081"


def get(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def login(username: str, password: str) -> int:
    req = urllib.request.Request(
        f"{AUTH}/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            return 200
    except urllib.error.HTTPError as e:
        return e.code


def rce() -> None:
    # Real shell execution of the harmless marker.
    print("vuln", get(f"{APP}/vuln/ping?host=127.0.0.1%3B%20printf%20LAB_RCE_OK"))


def rce_failed() -> None:
    # Command injection attempt the lab refuses before exec (no process event).
    print("vuln", get(f"{APP}/vuln/ping?host=127.0.0.1%3B%20rm%20-rf%20%2Ftmp%2Flab"))


def safe() -> None:
    print("safe", get(f"{APP}/safe/ping?host=127.0.0.1"))


def scan() -> None:
    for path in ("/admin", "/wp-login.php", "/server-status"):
        print(path, get(f"{APP}{path}"))


def brute_unauthorized() -> None:
    for i in range(12):
        # Two accounts behind one source IP, as in a shared-NAT office.
        user = "analyst" if i % 2 else "victim"
        login(user, "wrong-password")
    print("victim login", login("victim", "lab-victim"))


def brute_only() -> None:
    for i in range(12):
        login("analyst" if i % 2 else "victim", "wrong-password")


def mistakes() -> None:
    login("analyst", "wrong-1")
    login("analyst", "wrong-2")
    print("analyst login", login("analyst", "lab-analyst"))


SCENARIOS = {
    "T1": rce,
    "T2": rce_failed,
    "T3": scan,
    "T4": safe,
    "T5": brute_unauthorized,
    "T6": brute_only,
    "T7": mistakes,
    "T9": rce,
}

if __name__ == "__main__":
    # Suricata needs a moment after the container starts before its capture is useful.
    time.sleep(float(os.environ.get("RUNNER_WARMUP_SECONDS", "5")))
    name = sys.argv[1] if len(sys.argv) > 1 else ""
    if name not in SCENARIOS:
        sys.exit(f"scenario must be one of {', '.join(SCENARIOS)}")
    SCENARIOS[name]()
