# Phase 5 — final integration and release readiness

Date: 2026-11-13. Branch `hardening/kartika-mvp-sync`. GATER credentials remain
unavailable, so every live-agent claim below is BLOCKED, not simulated.

## A. Executive summary

- Baseline re-verified: 287 → **295 backend tests**, Ruff clean, frontend lint/build
  clean, **10/10** real-lab checks.
- Patch lifecycle is now visible in the product: the operator executor posts each run
  (including denials) to an operator-authenticated endpoint; the dashboard shows
  decision, reason, template, target, result and audit reference, read-only.
- Live AI: not run (no `LLM_*` values). Deterministic demo remains the honest core.
- Measured ingestion/early-warning latency over three runs per path; numbers are small
  and variance comes from the 5 s warning tick.
- No architecture change, no new attack types, no weakening of the gates.

## B. Current architecture

See `docs/architecture.md`. Summary: isolated lab → Suricata/access/process/auth
telemetry → authenticated ingest → incident + deterministic early warning → optional
LangGraph agents → rules gate (only writer of verdict) → dashboard; containment is
operator-token gated; patching is an operator CLI against a disposable clone, with
read-only records in the dashboard.

## C. Full integration results

| Layer | Result |
|---|---|
| Unit/integration (pytest, fake LLM) | **295 passed in 7.26 s** |
| Ruff | clean |
| Frontend lint/build | clean, 5 routes |
| Fixture replay | PASS (Phase 2) |
| Real deterministic lab | **10/10 PASS** |
| Real patch on isolated clone | applied + rolled back (Phase 4, re-run in Phase 5) |
| Live LLM agents | **BLOCKED** (`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` empty) |
| Incident → patch end-to-end | **BLOCKED** by design: real incident is `queued` → `not_decided` |

New in Phase 5: `patch_runs` table (migration 005), `POST /incidents/{id}/patch-runs`
(operator token, 401/503 fail-closed, 404 unknown incident, schema-validated),
`GET /incidents/{id}` includes the runs, dashboard card "Status patch (clone lab)".
Verified in the browser: denial card shows `DITOLAK · not_decided`,
`v1_sanitize_ping v1 → lab-web`, audit path.

## D. Security regression

| Invariant | Evidence |
|---|---|
| No LLM-only benign downgrade | `test_gate_rejects_llm_only_benign_downgrade`, `test_t4…`, pipeline test |
| RCE needs trusted execution evidence | `exec_unauthorized` required; authorized/unverified linkage stays attempted |
| No unauthorized auth ingest | separate `X-Auth-Ingest-Token`; cross-token tests 401; fail-closed 503 |
| No high/critical auto patch | policy tests + CLI `needs_human`; executor disabled by default |
| No automatic containment | decision/PAMELA/revert need `X-Operator-Token`; fail-closed |
| No LLM→shell | `grep -rn "subprocess|os.system|Popen|docker.sock" backend/app` → **0 hits** |
| No fabricated citations | `check_citations`; fake `ev_*` id test raises |
| Lab isolated | `docker network inspect pangbela-lab_lab --format {{.Internal}}` → `true`; app `docker ps` has no published ports |
| Forged/replayed approval | `T4-forged` attempted; `T4-replay` → `200 400` |
| Provider outage | timeout/rate-limit raised after one call; no retry storm |

Targeted security suites: 168 passed (`test_rules`, `test_auth_ingest`, `test_pamela`,
`test_patch_policy`, `test_llm_client`).

## E. T1–T9 status

| Test | Status | Layer |
|---|---|---|
| T1 successful RCE | PASS | real lab deterministic |
| T2 failed RCE | PASS | real lab deterministic |
| T3 scanner sweep | BLOCKED | needs pipeline for `unknown` classification |
| T4 IDS false positive | PASS | real alert + signed approval → benign |
| T5 brute force + unauthorized login | PASS | real lab |
| T6 brute force, no success | PASS | real lab |
| T7 ordinary mistakes | PASS | no incident opens |
| T8 prompt injection in logs | PASS deterministic; live BLOCKED | real traffic + fake-LLM unit |
| T9 missing host telemetry | PASS | real lab (`insufficient_telemetry`) |

```
PASS T1  PASS T2  PASS T5  PASS T6  PASS T7  PASS T8
PASS T4-approved  PASS T4-forged  PASS T4-replay  PASS T9
```

## F. PAMELA integration and patch evidence

- Patch eligibility is computed only from the persisted incident (`severity`,
  `attack_type`, `pipeline_state`, `verification_state`) plus the managed target and
  hash-checked template. No LLM input, no request-supplied patch content.
- Executor posts results for **real** incidents only; fixture runs stay fixtures and are
  labelled in the audit file.
- Real incident T2 (attempted/medium/verified but `queued`, because no LLM) is denied
  `not_decided`; that denial is visible in the dashboard and stored in `patch_runs`.
- Clone runs: applied (before/after hashes in audit) and forced-failure rollback proving
  the exploit works again. Canonical lab service untouched.
- High severity denial recorded; automatic patching default OFF.

## G. LLM provider status

GATER remains the configured baseline; `.env` has no LLM values. No provider was
substituted. Everything that depends on live agents (T3, live T8, real verdict→patch) is
**BLOCKED**. Outage behaviour is covered by unit tests: one call, explicit failure, no
write-capable response on incomplete output.

## H. Measured performance (three runs each, real lab)

| Path | Ingestion (s) | Early warning (s) |
|---|---|---|
| T1 (Suricata) | 0.844, 0.373, 0.859 → median **0.844** | 1.276, 0.277, 3.276 → median **1.276** |
| T5 (auth) | 0.040, 0.050, 0.050 → median **0.050** | 2.705, 1.169, 4.788 → median **2.705** |

Early warning runs on a 5 s tick, so its variance is expected. Investigation/report
latency and evidence-citation accuracy with a real model: **not measured (BLOCKED)**.
No comparison with historical GATER runs is claimed.

## I. Judging-rubric alignment

- **Relevance 25%** — deterministic triage first, AI explanation second; SOC-relevant
  evidence, uncertainty and human authorization.
- **Innovation 25%** — separation of code verdict and model proposal, signed benign
  operation (true false positive), source-authorized execution fact, bounded patch engine
  with hash-pinned template and clone rollback.
- **Functionality 25%** — real lab, 10 automated checks, real apply/rollback, dashboard
  patch visibility; honest blocked list for live AI.
- **Feasibility 15%** — Compose-only, env configuration, migrations, fail-closed
  credentials, isolated network, no backend shell/Docker access.
- **Documentation 10%** — architecture, demo script, decision/patch policies, log schema,
  Phase 2–5 reports, audit trail.

## J. Demo procedure

`docs/submission/DEMO_SCRIPT.md` (4 minutes): RCE, brute force, missing telemetry,
human-gated response, patch apply/rollback, AI status + outage fallback.

## K. Unresolved blockers

1. Live LLM validation and real verdict→patch eligibility (GATER credits).
2. T3 classification (needs pipeline; no fake `suspected` shortcut was added).
3. Process telemetry authority is app-level, not EDR-grade.
4. Patch runs on a disposable clone; canonical service is not patched.
5. Patch status is read-only; no dashboard trigger (by design).
6. Latency samples are small (n=3) and single-incident.

## L. Git summary

Commits on `hardening/kartika-mvp-sync` (no push, no merge): patch-run persistence + API
+ tests, executor posting, dashboard card, architecture/demo/report docs.

## M. Decision

**CONDITIONAL GO** for the hackathon demo: deterministic detection, evidence handling,
response safety, and lab patch lifecycle are reproducible and honest.
**NO-GO** for claiming live-agent validation, T3 PASS, or production auto-patching.
