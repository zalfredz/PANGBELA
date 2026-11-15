# Final MVP alignment report — 2026-11-15

Status: **PARTIAL** — deterministic MVP and release QC pass; live AI remains BLOCKED.
Branch: `feat/pangbela-final-mvp-alignment`, base `d29c81f`.

## 1. Executive summary

The repository already implemented the Phase 0–5 contract. The audit found two real gaps
in the *presentation* layer, not in detection: the dashboard gave no indication that AI
was unavailable when `llm_configured=false`, and the architecture document had no honest
statement of the proposed shadow-mode pilot. Both are corrected. No detection, ingestion,
policy or patch behaviour was changed.

Verified on this HEAD: **295 backend tests**, Ruff clean, frontend lint/build clean,
**10/10 real-lab checks**. AI live remains blocked (GATER credits); T3 remains blocked
because it needs the classification pipeline. Patch evidence remains clone-only.

## 2. Sources of truth

- This repository at `d29c81f` (phases 0–5).
- `docs/security/INCIDENT_DECISION_POLICY.md` (v1).
- `docs/security/PAMELA_PATCH_POLICY.md`.
- `docs/testing/PHASE2_REAL_LAB_REPORT.md`, `PHASE3_VALIDATION_REPORT.md`,
  `PHASE4_PATCH_REPORT.md`, `PHASE5_RELEASE_REPORT.md`.
- Final product contract supplied 2026-11-15 (no new requirements beyond alignment).

## 3. Gap-to-change traceability

| Requirement | Evidence in code | Status before | Change | Test | Status after |
|---|---|---|---|---|---|
| Rules gate sole writer of status/severity | `app/graph/rules.py::rules_gate` | OK | none | `test_rules.py`, `test_pipeline.py` | OK |
| RCE requires trusted unauthorized execution | `compute_facts`, `max_status` | OK | none | T1/T9 + unit | OK |
| Missing telemetry is explicit | `verification_state` | OK | none | `test_t9…`, lab T9 | OK |
| Separate auth ingest credential + producer | `api/ingest.py`, `auth_detect.py`, migration 004 | OK | none | `test_auth_ingest.py` | OK |
| Operator auth, fail-closed | `api/recommendations.py`, `api/patches.py` | OK | none | `test_pamela.py`, `test_patch_runs.py` | OK |
| Early warning independent of LLM | `app/runner.py` | OK | none | `test_runner.py`, lab runs | OK |
| Bounded AI, degraded mode visible | pipeline + fake-LLM tests | PARTIAL (UI silent) | `/health` banner on list and detail | `npm run lint/build`, browser check | OK |
| PAMELA clone-only, hash-pinned, rollback | `pamela_patch.py`, `lab/patch/` | OK | none | policy tests, real apply/rollback | OK |
| Patch lifecycle visible | `patch_runs`, API, UI card | OK | none | `test_patch_runs.py`, browser | OK |
| T3 reconnaissance | incident opens as `unknown/suspected` | BLOCKED | none | — | BLOCKED (needs pipeline) |
| Pilot/shadow explanation | absent | MISSING | `docs/architecture.md` pilot section | doc review | OK (proposal only) |

## 4. Security invariants

- Only `rules_gate` writes `incidents.status`/`severity`; proposals that differ are recorded
  as `rules_conflict`.
- RCE confirmation needs a linked web-server child, matching `request_id`, time window and
  `authorized=false`; authorized/unknown remains `attempted`.
- Auth events use `X-Auth-Ingest-Token`, alerts use `X-Ingest-Token`; neither is interchangeable;
  `producer` is stored.
- Boss/response endpoints require `X-Operator-Token`; no operators configured → 503.
- No `subprocess`, `os.system`, `Popen` or `docker.sock` usage in `backend/app` (0 grep matches,
  reviewed context: backend never executes commands).
- Lab network is `internal`, app publishes no ports; patch clone runs `--network none`,
  `--cap-drop ALL`, `no-new-privileges`, 256 MB, and is removed after each run.
- High/critical patch is denied; patching is off by default; canonical service untouched.

## 5. Scenario matrix (real lab, this HEAD)

Command: `python3 lab/verify_lab.py`

```
PASS T1  rce confirmed critical verified
PASS T2  rce attempted medium verified
PASS T5  brute_force confirmed high verified
PASS T6  brute_force attempted medium verified
PASS T7  incidents=0
PASS T8  rce attempted medium verified
PASS T4-approved  rce benign none verified
PASS T4-forged    rce attempted medium verified
PASS T4-replay    replay 200 400
PASS T9  attempted insufficient_telemetry
```

T3 is excluded by definition: scanner traffic produces `unknown/suspected/low` but the
deterministic early-warning loop only assesses classified attack types; the final verdict
needs the AI pipeline. No artificial classification was added.

## 6. Before/after QC

| Check | Before | After |
|---|---|---|
| Backend tests | 295 passed (baseline) | **295 passed in 9.76 s** |
| Ruff | clean | clean |
| Frontend lint/build | clean | clean |
| Real lab checks | 10/10 (Phase 5) | **10/10 re-run 2026-11-15** |
| Shell/Docker use in backend | 0 | 0 |
| Migrations | 005 applied | unchanged |

Frontend change verified in a real browser: dashboard and incident detail show
“AI belum dikonfigurasi…” when `/health` reports `llm_configured:false`.

## 7. Latency

No new latency run was performed today. Baseline remains the Phase 5 measurement
(n=3 per path, local lab, one incident at a time):

| Path | Ingestion raw (s) | Early warning raw (s) | Median warning |
|---|---|---|---|
| RCE | 0.844, 0.373, 0.859 | 1.276, 0.277, 3.276 | 1.276 s |
| Brute force | 0.040, 0.050, 0.050 | 2.705, 1.169, 4.788 | 2.705 s |

These are not an SLA; the 5 s warning tick dominates variance.

## 8. AI validation disclosure

- Four agents, schema validation, citation checks, untrusted-data fencing, retry caps and
  provider-fault tests exist and pass with the fake SDK.
- **No live provider call was made.** `LLM_*` is empty; GATER credits are unavailable.
- OpenCode Go is not used for SOC inference: its published policy targets coding-agent
  traffic and requires session/identity headers; using it here would misrepresent the
  workload.
- No claim of prompt-injection resistance for a real model; T8 is proven only at the
  deterministic layer.

## 9. PAMELA disclosure

Eligibility is deterministic and unit-tested; the executor patches only a disposable
clone, verifies health/attack-blocked/safe behaviour, rolls back on failure, and records
audit files plus `patch_runs`. Real evidence from Phase 4/5 remains: `applied`,
`rolled_back` with the exploit working again, `needs_human` for high severity, and
`not_decided` for a real queued incident. No production patching, no canonical-service
mutation.

## 10. Roadmap and pilot

Single internal web service, read-only telemetry with written permission, shadow mode
(no blocking or patching), analyst comparison, then human-approved containment. See
`docs/architecture.md` “Pilot path (shadow mode, not built)”. Independent host sensor
(Falco/eBPF) and OT/ICS are future work.

## 11. Known limitations

Shared-NAT logins aggregate per source IP; process telemetry is application-instrumented,
so `authorized` is only as trustworthy as the app; no independent EDR sensor; one patch
template; patch status read-only; small latency sample; live AI untested.

## 12. Evidence commands

```sh
cd backend && uv run pytest -q && uv run ruff check . ../shipper
cd frontend && npm run lint && npm run build
python3 lab/verify_lab.py
grep -rn "subprocess\|os.system\|Popen\|docker.sock" backend/app   # 0 lines
```

Raw lab PASS lines are in the terminal transcript for 2026-11-15 and the harness prints
them on every run; no screenshot or mock output is claimed.
