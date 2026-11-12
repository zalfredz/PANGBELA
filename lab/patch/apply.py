#!/usr/bin/env python3
"""Allowlisted patch executor for the isolated lab (Phase 4).

The policy engine (backend/app/pamela_patch.py) decides eligibility. This script applies
the patch to a **disposable clone** of the managed lab image: the canonical lab service
stays untouched, so T1/T2/T4 scenarios remain reproducible after a patch run. The clone
is created from the exact image the target runs, patched, restarted, tested, rolled back
on failure, and removed.

    python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable
    python3 lab/patch/apply.py --incident <uuid> --enable
    python3 lab/patch/apply.py --incident-file ... --enable --dry-run
    python3 lab/patch/apply.py --incident-file ... --enable --force-failure

Nothing here is reachable from the backend or the LLM: it is an operator-run lab tool.
"""

import argparse
import difflib
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app.pamela_patch import PatchConfig, Target, Template, check  # noqa: E402

COMPOSE = ["docker", "compose", "-f", str(ROOT / "lab/docker-compose.yml"), "--env-file",
           str(ROOT / ".env")]
TEMPLATE_ID = "v1_sanitize_ping"
EXPLOIT = "/vuln/ping?host=127.0.0.1%3B%20printf%20LAB_RCE_OK"
SAFE = "/safe/ping?host=127.0.0.1"
AUDIT = ROOT / "lab/patch/audit"
STATE = ROOT / "lab/patch/state/app.py.before"

PROBE = """
import sys, urllib.error, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as r:
        print(r.status, r.read().decode()[:120])
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode()[:120])
except Exception as e:
    print("error", type(e).__name__, e)
"""


def docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], cwd=ROOT, check=True, capture_output=True,
                          text=True)


def compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(COMPOSE + list(args), cwd=ROOT, check=True, capture_output=True,
                          text=True)


def target_container() -> str:
    return compose("ps", "-q", "app").stdout.strip()


def read_file(container: str, path: str) -> str:
    return docker("exec", container, "cat", path).stdout


def write_file(container: str, path: str, data: str) -> None:
    tmp = STATE.parent / "upload.tmp"
    tmp.write_text(data)
    docker("cp", str(tmp), f"{container}:{path}")


def probe(container: str, url_path: str) -> str:
    return docker("exec", container, "python", "-c", PROBE,
                  f"http://127.0.0.1:8080{url_path}").stdout.strip()


def wait_healthy(container: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if probe(container, "/healthz").startswith("200"):
            return True
        time.sleep(0.5)
    return False


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def fetch_incident(incident_id: str) -> dict:
    with urllib.request.urlopen(f"http://localhost:8000/incidents/{incident_id}", timeout=10) as r:
        return json.load(r)["incident"]


def audit(record: dict) -> Path:
    AUDIT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = AUDIT / f"{stamp}-{record.get('incident', 'patch')}.json"
    record["recorded_at"] = datetime.now(UTC).isoformat()
    path.write_text(json.dumps(record, indent=2) + "\n")
    return path


def checks(container: str) -> list[dict]:
    health = probe(container, "/healthz")
    exploit = probe(container, EXPLOIT)
    safe = probe(container, SAFE)
    return [
        {"check": "health", "value": health, "pass": health.startswith("200")},
        {"check": "attack_blocked", "value": exploit,
         "pass": exploit.startswith("400") and "LAB_RCE_OK" not in exploit},
        {"check": "safe_endpoint", "value": safe, "pass": safe.startswith("200")},
    ]


def vulnerable_again(container: str) -> bool:
    exploit = probe(container, EXPLOIT)
    return exploit.startswith("200") and "LAB_RCE_OK" in exploit


def patch_clone(clone: str, patched: str, record: dict) -> tuple[bool, list[dict]]:
    current = read_file(clone, "/lab/app.py")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(current)
    record["before_sha256"] = sha(current)
    write_file(clone, "/lab/app.py", patched)
    record["after_sha256"] = sha(read_file(clone, "/lab/app.py"))
    docker("restart", clone)
    if not wait_healthy(clone):
        return False, [{"check": "health", "value": "timeout", "pass": False}]
    return True, checks(clone)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--incident")
    ap.add_argument("--incident-file", help="policy fixture, not detector output")
    ap.add_argument("--template", default=TEMPLATE_ID)
    ap.add_argument("--enable", action="store_true", help="arm auto patching")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force-failure", action="store_true")
    args = ap.parse_args()

    cfg = PatchConfig(
        enabled=args.enable or os.environ.get("PATCH_AUTO_ENABLE") == "1",
        max_severity=os.environ.get("PATCH_MAX_SEVERITY", "medium"),
    )
    if not args.incident and not args.incident_file:
        ap.error("--incident or --incident-file is required")
    incident = (
        load_json(Path(args.incident_file)) if args.incident_file else fetch_incident(args.incident)
    )
    if args.incident_file:
        incident["fixture"] = True

    manifest = load_json(ROOT / f"lab/patch/templates/{args.template}/manifest.json")
    template_text = (ROOT / f"lab/patch/templates/{args.template}/{manifest['file']}").read_text()
    template = Template(manifest["id"], manifest["version"], manifest["sha256"],
                        manifest["applies_to"])
    raw_target = next(
        (t for t in load_json(ROOT / "lab/patch/assets.json")["targets"]
         if t["image"] == manifest["applies_to"]),
        None,
    )
    target = Target(**raw_target) if raw_target else None

    decision = check(incident, template, sha(template_text), target, cfg)
    record = {
        "incident": incident.get("id", args.incident_file),
        "decision": decision.__dict__,
        "template": manifest,
        "target": raw_target,
        "fixture": incident.get("fixture", False),
    }
    if not decision.allowed:
        path = audit({**record, "result": "denied"})
        print(json.dumps({**decision.__dict__, "audit": str(path)}))
        return 2

    # Target identity: the clone must be built from the image the managed target runs.
    source = target_container()
    image_id = docker("inspect", source, "--format", "{{.Image}}").stdout.strip()
    image_name = docker("inspect", source, "--format", "{{.Config.Image}}").stdout.strip()
    record["source_container"] = source
    record["image"] = {"name": image_name, "id": image_id}
    if image_name.split(":")[0] != manifest["applies_to"]:
        path = audit({**record, "result": "denied", "reason": "running_image_mismatch"})
        print(json.dumps({"allowed": False, "reason": "running_image_mismatch", "audit": str(path)}))
        return 2

    current = read_file(source, "/lab/app.py")
    if args.dry_run:
        diff = list(difflib.unified_diff(current.splitlines(), template_text.splitlines(),
                                        "current", "template", lineterm=""))
        path = audit({**record, "result": "dry_run", "diff_lines": len(diff)})
        print("\n".join(diff[:40]))
        print(json.dumps({"result": "dry_run", "audit": str(path)}))
        return 0

    clone = f"pangbela-patch-{uuid.uuid4().hex[:8]}"
    docker("create", "--name", clone, "--network", "none", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true", "--memory", "256m",
           "-e", "PROCESS_LOG_DISABLED=1", "-e", "LAB_LOG_DIR=/tmp",
           image_id, "python", "app.py")
    record["clone"] = clone
    try:
        docker("start", clone)
        if not wait_healthy(clone):
            path = audit({**record, "result": "failed", "reason": "clone_unhealthy"})
            print(json.dumps({"result": "failed", "audit": str(path)}))
            return 1
        ok, results = patch_clone(clone, template_text, record)
        record["checks"] = results
        ok = ok and all(c["pass"] for c in results) and not args.force_failure
        if args.force_failure:
            record["forced_failure"] = True
        if not ok:
            write_file(clone, "/lab/app.py", STATE.read_text())
            docker("restart", clone)
            wait_healthy(clone)
            restored = vulnerable_again(clone)
            record["rollback_check"] = {
                "vulnerable_again": restored,
                "value": probe(clone, EXPLOIT),
            }
            result = "rolled_back" if restored else "rollback_failed"
            path = audit({**record, "result": result})
            print(json.dumps({"result": result, "audit": str(path)}))
            return 1 if restored else 3
        path = audit({**record, "result": "applied"})
        print(json.dumps({"result": "applied", "audit": str(path)}))
        return 0
    finally:
        subprocess.run(["docker", "rm", "-f", clone], capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
