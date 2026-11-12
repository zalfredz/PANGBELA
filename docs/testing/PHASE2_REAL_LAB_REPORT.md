# Phase 2 — real lab integration report

Date: 2026-11-13. Branch `hardening/kartika-mvp-sync`. Deterministic layer only: no LLM
was called (GATER credits unavailable), so no live-agent result is claimed here.

**Superseded in Phase 3:** T4 is now a true false-positive test (real alert + signed
maintenance approval, PASS); `/ingest/auth` has its own producer credential; T8 has a
real-lab deterministic run. See `docs/testing/PHASE3_VALIDATION_REPORT.md`. The T4 row and
the "auth events bypass the shipper" note below are historical for Phase 2.

## A. Executive summary

An isolated Docker lab now produces **real** network, access, process and authentication
telemetry, and the existing pipeline turns it into incidents with deterministic
assessments: the ingest → Suricata → shipper → incident → rules/evidence path works
without an LLM.

RCE confirmation was tightened: a linked child process is no longer enough. The lab's
own execution policy must say `authorized=false`. Missing host telemetry degrades to
`insufficient_telemetry` instead of confirming.

Seven of nine scenarios have real-lab evidence. T3 needs the agent pipeline (no
provisional assessment exists for an unclassified alert) and T8 needs a real LLM. Both
are marked BLOCKED, not passed.

## B. Files changed

| File | Change |
|---|---|
| `backend/app/graph/rules.py` | RCE `confirmed` now requires `exec_unauthorized`; linked-but-authorized/unverified stays `attempted`; unverified linkage is `partially_verified` |
| `backend/app/evidence/process_log.py` | carries the `authorized` boolean from the process sensor |
| `backend/tests/test_rules.py` | new invariants + negative tests (legit child, missing authorization) |
| `lab/app.py` | vulnerable + safe endpoints, real `/proc` process telemetry, allowlisted marker |
| `lab/auth.py` | synthetic users, CIDR-based authorization, writes and posts auth events |
| `lab/runner.py` | one scenario per invocation |
| `lab/suricata/lab.rules` | RCE (sid 1000001) and scanner (sid 1000009) signatures |
| `lab/docker-compose.yml` | isolated internal network, shared volumes, Suricata in the app's netns |
| `lab/run_scenario.sh`, `lab/verify_lab.py` | reset + run + assert, real traffic |
| `lab/samples/T1/*`, `lab/samples/T5/auth.jsonl` | actual captured telemetry |
| `lab/README.md` | start, reset, safety and limits |
| `docs/security/INCIDENT_DECISION_POLICY.md` | new RCE evidence rule and assurance ceiling |
| `docker-compose.yml` | default network gets the fixed name `ai-soc-net` for the lab |

## C. Architecture integration

```
runner ──HTTP──> app:8080 ──spawns /bin/sleep | /bin/sh (marker only)
                   │  writes access.log + process.log (/lab-logs)
                   │
                   └── same netns ──> suricata (eve.json → ai-soc-suricata-logs)
runner ──HTTP──> auth:8081 ── writes auth.log + POST /ingest/auth
                                   │
main stack: shipper tails eve.json ─┴─> backend: incidents, evidence, provisional
```

Volumes are the existing `ai-soc-lab-logs` / `ai-soc-suricata-logs`; the lab network is
`internal` and the app publishes no ports. Suricata shares the app's network namespace,
which is why it sees the traffic at all on a Docker bridge.

## D. Lab execution evidence

Suricata: `Suricata version 8.0.8 RELEASE running in SYSTEM mode`; rules loaded from
`lab/suricata/lab.rules` after replacing a pcre that the 8.x parser rejected with a hex
content match (`content:"|3b|"; http_uri;`).

T1 request and captured events (see `lab/samples/T1/`):

```
access:  /vuln/ping?host=127.0.0.1%3B%20printf%20LAB_RCE_OK  src 172.28.0.4
process: exe=/usr/bin/dash parent_exe=/usr/local/bin/python3.12
         request_id=37349d6d1b0343b2b8caeeb53e5dc5d1 authorized=false
eve:     alert sid 1000001 "LAB Web RCE command injection attempt"
```

The access and process rows share the request id; the alert arrives through the existing
shipper as `accepted=1`. The app returned `200` with the harmless marker.

## E. T1–T9 results

Command: `python3 lab/verify_lab.py` (real traffic, deterministic layer, no LLM).

```
PASS T1 got=('rce', 'confirmed', 'critical', 'verified')
PASS T2 got=('rce', 'attempted', 'medium', 'verified')
PASS T5 got=('brute_force', 'confirmed', 'high', 'verified')
PASS T6 got=('brute_force', 'attempted', 'medium', 'verified')
PASS T7 incidents=0
PASS T4 incidents=0
PASS T9 got=('attempted', 'insufficient_telemetry')
```

| Test | Real lab | Result | Notes |
|---|---|---|---|
| T1 successful RCE | yes | PASS | confirmed/critical once policy says `authorized=false` |
| T2 failed RCE | yes | PASS | app refuses before exec; alert + request → attempted/medium |
| T3 scanner sweep | yes | **BLOCKED** | incident opens as `unknown`, default `suspected/low`; deterministic runner has no provisional verdict for an unclassified alert, so the final verdict needs the pipeline |
| T4 IDS false positive | partial | **BLOCKED** | safe endpoint produces no alert/incident (`PASS T4 incidents=0`), but there is no trusted-benign path that fires the IDS and then proves benign. No fabricated case was added |
| T5 brute force + unauthorized login | yes | PASS | 12 failures, victim login `authorized=false` → confirmed/high |
| T6 brute force, no success | yes | PASS | attempted/medium |
| T7 ordinary mistakes | yes | PASS | 2 failures + authorized login; no incident opens (threshold not reached) |
| T8 prompt injection in logs | rules only | **BLOCKED (live)** | `test_t8_injected_benign_proposal_does_not_change_verdict` passes with fake LLM; real-provider effect untested |
| T9 RCE without host telemetry | yes | PASS | app recreated with `PROCESS_LOG_DISABLED=1`, `process.log` deleted → attempted/medium/insufficient_telemetry |

Layer separation:

- Unit tests: PASS (`254 passed`).
- Synthetic fixture replay: PASS (previous phase, unchanged).
- Real lab integration: PASS for T1/T2/T5/T6/T7/T9 (deterministic layer), T4 partial.
- Live LLM provider: **BLOCKED** (GATER credits).

## F. Security validation

- LLM-only benign downgrade stays removed; `rules_gate` never applies a proposal that
  differs from `max_status`.
- Confirmation requires the policy fact: linked execution with no `authorized` field is
  `partially_verified`, not `confirmed` (`test_verification_state`, new case).
- Authorized child (`authorized=true`) cannot confirm (`test_legitimate_authorized_child_is_never_confirmed`).
- Missing process source → `insufficient_telemetry` (T9, real lab).
- Operator auth for decision/PAMELA/revert unchanged (`X-Operator-Token`, fail-closed).
- Lab: internal network, no published ports, `cap_drop: ALL` on app/auth/runner,
  read-only rootfs, `no-new-privileges`, memory limits, only `printf LAB_RCE_OK` may run
  after the injection separator; every other payload is refused before exec.
- Suricata runs with the minimum capability set it needs to capture and drop privileges
  (`NET_ADMIN, NET_RAW, DAC_OVERRIDE, SETUID, SETGID, CHOWN, SYS_NICE, SETPCAP`).

## G. Remaining blockers and risks

1. **P0 GATER**: no live agent run. Live LLM column is empty by design.
2. **P0 assurance**: `authorized` is written by the app-instrumented fallback. Real
   Falco/eBPF telemetry would make it tamper-resistant; the schema is ready for it.
3. **P0 T3/T4**: T3 needs the pipeline to settle `unknown`; T4 needs a trusted benign
   source (approved-operation list or signed health-check policy) that the lab does not
   have yet.
4. **Operational**: recreating `app` alone orphans Suricata (it joins the app's netns).
   `verify_lab.py` and `lab/README.md` always recreate both.
5. Auth events bypass the file-tailing shipper (the auth service posts them) because the
   shipper's follow mode skips pre-existing lines. Same endpoint, same schema, but it is
   a deviation from the "shipper only" flow.
6. One runner IP for all scenarios; reset is mandatory between runs (`auth_events` too).

## H. Git summary

Two local commits on `hardening/kartika-mvp-sync` (security hardening, real lab +
evidence); nothing pushed or merged. Files listed in section B.

## I. Decision

**CONDITIONAL GO** for the deterministic, evidence-grounded demo: real lab telemetry,
real Suricata alerts, correct attempted/confirmed/insufficient behaviour, no false
confirmation without host telemetry, and protected response endpoints.

**NO-GO** for any claim that the agent pipeline was validated end to end, that T3/T4 pass,
or that T8 survives a real LLM prompt injection. Those need GATER and the two missing
evidence sources, not more code.
