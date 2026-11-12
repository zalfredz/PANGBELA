#!/usr/bin/env python3
"""End-to-end check of the deterministic layer against real lab traffic.

For each scenario: reset database and log files, run the attack script, wait for the
early-warning assessment, and compare it with the expected result. No LLM is involved,
so this validates ingest -> correlation -> rules -> evidence, not agent behaviour.

    python3 lab/verify_lab.py            # all scenarios
    python3 lab/verify_lab.py T1 T2      # selected
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

COMPOSE = ["docker", "compose", "-f", "lab/docker-compose.yml", "--env-file", ".env"]
API = "http://localhost:8000"

# scenario -> (attack_type, status, severity, verification). None means "no incident".
EXPECTED = {
    "T1": ("rce", "confirmed", "critical", "verified"),
    "T2": ("rce", "attempted", "medium", "verified"),
    "T5": ("brute_force", "confirmed", "high", "verified"),
    "T6": ("brute_force", "attempted", "medium", "verified"),
    "T7": None,
    "T8": ("rce", "attempted", "medium", "verified"),
}


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def reset() -> None:
    run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "soc",
            "-d",
            "soc",
            "-qc",
            "TRUNCATE incidents, auth_events, lab_status CASCADE",
        ]
    )
    for path in ("access.log", "process.log", "auth.log"):
        run(COMPOSE + ["exec", "-T", "app", "sh", "-c", f": > /lab-logs/{path}"])
    run(COMPOSE + ["exec", "-T", "suricata", "sh", "-c", ": > /var/log/suricata/eve.json"])


def incidents() -> list[dict]:
    with urllib.request.urlopen(f"{API}/incidents", timeout=10) as r:
        return json.load(r)["items"]


def wait_assessed(timeout: float = 30.0) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        items = incidents()
        if items and all(i["provisional_status"] for i in items):
            return items
        time.sleep(2)
    return incidents()


def check(name: str) -> tuple[bool, str]:
    want = EXPECTED[name]
    run(COMPOSE + ["run", "--rm", "--build", "runner", "python", "runner.py", name])
    items = wait_assessed()
    if want is None:
        return (not items), f"incidents={len(items)}"
    if not items:
        return False, "no incident"
    i = items[0]
    got = (i["attack_type"], i["provisional_status"], i["provisional_severity"],
           i["provisional_verification"])
    return got == want, f"got={got}"


def t4() -> list[tuple[str, bool, str]]:
    """Approved maintenance job: real IDS alert, signed approval, real execution."""
    out = []
    for name, args, want in (
        ("T4-approved", [], ("rce", "benign", "none", "verified")),
        ("T4-forged", ["--forged"], ("rce", "attempted", "medium", "verified")),
    ):
        reset()
        run(COMPOSE + ["run", "--rm", "--build", "maintenance", "python", "maintenance.py", *args])
        items = wait_assessed()
        if not items:
            out.append((name, False, "no incident"))
            continue
        i = items[0]
        got = (i["attack_type"], i["provisional_status"], i["provisional_severity"],
               i["provisional_verification"])
        out.append((name, got == want, f"got={got}"))
    # Replay: the same nonce must be refused the second time.
    reset()
    r = run(COMPOSE + ["run", "--rm", "--build", "maintenance", "python", "maintenance.py", "--replay"])
    last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    out.append(("T4-replay", last == "replay 200 400", last))
    return out


def t9() -> tuple[bool, str]:
    """Host telemetry missing: the same RCE traffic must not be confirmed."""
    run(
        COMPOSE + ["up", "-d", "--force-recreate", "app", "suricata"],
        env={**os.environ, "PROCESS_LOG_DISABLED": "1"},
    )
    time.sleep(8)
    reset()
    run(COMPOSE + ["exec", "-T", "app", "sh", "-c", "rm -f /lab-logs/process.log"])
    run(COMPOSE + ["run", "--rm", "--build", "runner", "python", "runner.py", "T9"])
    items = wait_assessed()
    if not items:
        return False, "no incident"
    i = items[0]
    got = (i["provisional_status"], i["provisional_verification"])
    ok = got == ("attempted", "insufficient_telemetry")
    # Restore the normal app for the next run.
    run(COMPOSE + ["up", "-d", "--force-recreate", "app", "suricata"])
    return ok, f"got={got}"


if __name__ == "__main__":
    requested = sys.argv[1:]
    names = [n for n in (requested or EXPECTED) if n in EXPECTED]
    failures = 0
    for name in names:
        reset()
        ok, detail = check(name)
        print(f"{'PASS' if ok else 'FAIL'} {name} {detail}")
        failures += not ok
    if not sys.argv[1:] or "T4" in sys.argv[1:]:
        for name, ok, detail in t4():
            print(f"{'PASS' if ok else 'FAIL'} {name} {detail}")
            failures += not ok
    if not sys.argv[1:] or "T9" in sys.argv[1:]:
        reset()
        ok, detail = t9()
        print(f"{'PASS' if ok else 'FAIL'} T9 {detail}")
        failures += not ok
    sys.exit(1 if failures else 0)
