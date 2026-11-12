# Baseline reconciliation — Kartika MVP hardening

Date: 2026-11-13. Branch: `hardening/kartika-mvp-sync`, based on `main` @ `8f2c49b`
(the only commit in the clone). Nothing was pushed or merged.

## How this was produced

| Check | Command | Result |
|---|---|---|
| Working tree before changes | `git status --short --branch` | clean, `main...origin/main` |
| Baseline backend suite | `cd backend && uv run pytest -q` | `248 passed in 6.09s` |
| Baseline lint | `uv run ruff check . ../shipper` | `All checks passed!` |
| Baseline frontend lint/build | `npm run lint`, `npm run build` | clean, 5 routes built |
| Runtime smoke (fixture replay) | `shipper.py --once` with `backend/tests/fixtures/` | 3 alerts → 1 incident, 3 evidence rows, 3 SSE `evidence_added` events |
| Health | `curl localhost:8000/health` | `{"db":"ok","llm_configured":false}` |

The fixture replay proves the ingest → correlate → evidence → SSE path without an LLM.
It is **not** a lab capture and is not counted as T1–T9 evidence.

## Status legend

- **Verified** — acceptance check ran in this repository and passed.
- **Unverified** — code exists and unit tests pass, but the real-provider or real-lab
  acceptance check has not run.
- **Partial** — some required behaviour is missing.
- **Missing** — no implementation.
- **Blocked** — needs infrastructure or a decision we do not have.

## Traceability matrix

| Requirement | Existing code | Current behaviour | Gap | Priority | Planned change | Test | Result |
|---|---|---|---|---|---|---|---|
| Suricata EVE ingest | `app/ingest/eve_parser.py`, `api/ingest.py` | alert events accepted, non-alerts ignored, bad token 401 | none found | P0 | — | `test_ingest.py` | Verified |
| Auth-log ingest | `api/ingest.py`, `ingest/auth_detect.py` | failures open/attach incidents; successes recorded | none found | P0 | — | `test_ingest.py`, `test_team_baseline.py` | Verified |
| Grouping window | `ingest/grouping.py`, `INCIDENT_GROUP_WINDOW_SECONDS` | one incident per src/dest inside window | window is DRAFT, config-driven | P1 | keep | `test_ingest.py` | Verified |
| Shipper replay / tail | `shipper/shipper.py` | posts lines, offset survives restart, fatal 401 | none found | P0 | — | `test_shipper.py` | Verified |
| Normalized event contract | `evidence/store.py` | `source`, `ts`, `src_ip`, `fields`, `raw`, `collected_by` | no `ingest_time`, `raw_sha256`, `request_id`-level schema; fields differ per source | P1 | document, do not migrate mid-MVP | `test_evidence*` | Partial |
| Evidence provenance | `evidence/store.py`, `redact.py` | raw line stored, id `ev_*`, citations must exist | no hash of raw lines; retention policy absent | P1 | hash column is a schema change; recorded as gap | `test_rules.py::test_unknown_report_reference_is_rejected` | Partial |
| Deterministic rules gate | `app/graph/rules.py` | code sets status; agents propose | **LLM could downgrade attempted/suspected to benign** | P0 | removed LLM-only benign downgrade; proposals become conflicts | new `test_gate_rejects_llm_only_benign_downgrade`, `test_pipeline.py` | Verified (this branch) |
| RCE confirmation | `rules.py::compute_facts` + `max_status` | parent is web server **and** `request_id` matches **and** inside −2 s/+10 s → `confirmed` | does not distinguish *authorized* child process from exploit; `WEB_SERVER_EXES` may be empty | P0 | **not changed**: needs lab process policy (`authorized`/allowlist) to verify; see `docs/security/INCIDENT_DECISION_POLICY.md` | `test_rules.py` RCE branches; negative "legitimate child" test **missing** | Partial |
| RCE with missing host telemetry | `rules.py::verification_state` | `insufficient_telemetry`, never confirmed | none found | P0 | — | `test_t9_missing_host_telemetry_never_confirmed` | Verified |
| Brute-force detection | `ingest/auth_detect.py`, `rules.py` | ≥10 failures/120 s → `attempted`; only `authorized=false` success → `confirmed` | success with no `authorized` field is partial (correct); NAT/shared-IP grouping not modelled | P1 | keep; document NAT limitation | `test_t5*`, `test_t6`, `test_t7` | Verified |
| LLM provider (GATER) | `app/llm/client.py`, `.env` | OpenAI-compatible client, schema retry | **credits exhausted**; no live call this session | P0 | none; baseline preserved | `test_llm_client.py` (fake client only) | Blocked |
| Agent pipeline (4 agents) | `app/graph/pipeline.py` | LangGraph DAG, citation check, forensics skip on `ruled_benign` | only exercised with fake LLM | P0 | keep; benign proposal now cannot change verdict | `test_pipeline.py` | Unverified (real provider) |
| Prompt-injection containment | `agents/base.py` untrusted block | payload only inside `<untrusted_data>` | T8 with real LLM not run | P0 | keep | `test_attacker_content_only_inside_untrusted_block` | Unverified (real provider) |
| Early warning | `app/runner.py` | rules-only provisional assessment, SSE `early_warning`, no LLM needed | only fires for classified attack types; `unknown` stays null | P0 | keep | `test_runner.py` | Verified at code level |
| Citation check | `rules.py::check_citations` | unknown `ev_*` id fails the run | applies to findings and `report_md` only (by design) | P0 | keep | `test_check_citations*` | Verified |
| Response authorization | `api/recommendations.py` | decision/PAMELA/revert had **no auth**; `decided_by` came from the request body | anyone could approve, reject, revert, or sign as anyone | P0 | `OPERATOR_TOKENS` map, `X-Operator-Token`, server-derived name, fail-closed 503 | new auth tests in `test_api.py`, `test_pamela.py` | Verified (this branch) |
| Enforcement pull auth | `api/recommendations.py::enforcement` | `X-Enforcement-Token`, separate from LLM key, 503 when unset | none found | P0 | — | `test_pamela.py` enforcement tests | Verified |
| Protected IPs | `app/pamela.py` | never blocked by PAMELA or a person | none found | P0 | — | `test_protected_ip_is_never_blocked` | Verified |
| PAMELA severity gate | `pamela.py::gate` | acts only at `PAMELA_MAX_SEVERITY` (default medium), only when pipeline done | policy is containment only; no patch execution | P0/P1 | documented; patch manager not implemented | `test_pamela_refuses_high_severity` | Partial |
| Auto-patching (Low/Medium) | — | **does not exist**: `patch_endpoint` is `manual_only` | whole patch registry/dry-run/rollback chain missing | P1 | not implemented; would be unverifiable without lab | `test_pamela_cannot_patch` | Missing |
| High/Critical auto-patch protection | `pamela.py::gate` | high/critical → `needs_human` | holds for all actions, not just patches | P0 | keep | `test_pamela_refuses_high_severity` | Verified |
| Severity / confidence semantics | `rules.py` | static map; confidence = coverage − penalties, labelled heuristic | asset criticality and impact dimensions absent | P1 | document; no fake precision | `test_severity_map`, `test_confidence` | Partial |
| Dashboard | `frontend/app/*` | list, detail, SSE, recommendations, tests page | no patch status, no operator token UI beyond a session field, no latency panel | P1 | operator token field added; rest recorded | `npm run lint`, `npm run build` | Partial |
| Scenario results | `api/tests_api.py` | compares latest incident per `src_ip` to `test_cases` | table empty; lab assigns IPs | P0 | none (team-owned data) | `test_results_*` | Blocked |
| Isolated lab | — | **absent** | no vulnerable app, no Suricata rules, no process telemetry, no captures | **P0** | out of scope for this branch; described in `docs/security/INCIDENT_DECISION_POLICY.md` §Lab | — | Missing |
| T1–T9 scenarios | `tests/test_rules.py` shape only | rule-path checks with in-memory facts | not real lab runs; T4 expectation changed with the gate fix | P0 | recorded honestly; no PASS claims | `test_t1…test_t9` | Unverified |
| Health / migrations / compose | `app/main.py`, `scripts/migrate.py`, `docker-compose.yml` | 9 tables, health reports DB + LLM state | fresh-DB order (`up` before migrate) breaks backend | P0 | README fixed earlier then reverted with the tree; re-apply only with team approval | `curl /health`, migrate run | Verified |
| Docs | `README.md`, `docs/build-spec.md`, `docs/log-schema.md` | spec is detailed | no threat model, no submission pack | P1 | this file + decision policy | — | Partial |

## Changes made on this branch

1. `backend/app/graph/rules.py` — a status different from `max_status()` is recorded as a
   conflict and never applied. LLM-only benign downgrades are gone.
2. `backend/app/api/recommendations.py` + `backend/app/config.py` — operator
   authentication for decision / PAMELA hand-off / revert. Identity is derived from the
   token map; request bodies cannot choose it; endpoints fail closed (503) when no
   operators are configured.
3. `backend/tests/*` — tests updated to the new invariants, plus new negative tests for
   the bypasses above.
4. `frontend/lib/api.ts`, `frontend/app/incidents/[id]/incident-view.tsx` — the dashboard
   sends `X-Operator-Token` (sessionStorage) instead of a free-text name.
5. `.env.example` — `OPERATOR_TOKENS` documented.

## Unresolved blockers (do not report as done)

- **P0 lab**: no `lab/`, no real captures, therefore no T1–T9 evidence. Verdict quality
  of the whole pipeline is unproven end to end.
- **P0 GATER**: credits exhausted; real-provider checks (`check_llm.py`,
  `run_fixture_pipeline.py`) cannot run. The pipeline remains "unverified".
- **P0 RCE authorization proof**: `confirmed` still means "web-server child with a
  matching request id", not "unauthorized execution". Needs a lab-side policy field.
- **P1 auto-patch**: not implemented. The current policy table therefore only covers
  containment/recommendation actions.
