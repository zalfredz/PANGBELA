# Phase 4 — controlled auto-patching report

Date: 2026-11-13. Branch `hardening/kartika-mvp-sync`. Phase 0–3 preserved. GATER remains
unavailable, so no live-agent result is claimed.

## A. Executive summary

- PAMELA is split into two policies: containment (unchanged, human/operator-token gated)
  and patching (new, default OFF).
- One allowlisted, versioned, hash-checked patch template exists (`v1_sanitize_ping`).
- The executor patches a disposable clone of the managed lab image, verifies health, the
  blocked exploit and the safe endpoint, and rolls back automatically on failure.
- Real evidence: one successful apply, one forced-failure rollback with the exploit
  working again, plus denials (auto-patch off, high severity, undecided real incident).
- A real incident cannot become eligible without a finished LLM pipeline; that path is
  recorded as BLOCKED, not faked.

## B. Files changed

| File | Change |
|---|---|
| `backend/app/pamela_patch.py` | pure patch-policy engine, separate from containment |
| `backend/tests/test_patch_policy.py` | 18 tests: every allow/deny branch |
| `lab/patch/templates/v1_sanitize_ping/` | versioned template + manifest with SHA-256 |
| `lab/patch/assets.json` | managed target registry (`lab-web`, criticality `lab`) |
| `lab/patch/apply.py` | operator executor: dry run, clone, snapshot, apply, verify, rollback, audit |
| `lab/patch/fixtures/eligible_medium.json`, `denied_high.json` | clearly labelled policy fixtures |
| `lab/patch/audit/*.json` | real apply/rollback/denial evidence |
| `docs/security/PAMELA_PATCH_POLICY.md` | policy, workflow, ceiling |
| `docs/security/INCIDENT_DECISION_POLICY.md`, `README.md` | status updates |

## C. Policy engine and separation

`check(incident, template, template_sha256, target, cfg)` returns a stable reason code.
Ordered gates: armed → severity → attack type → pipeline state → verification → template
exists/hash → managed target → asset class → image match. Containment code
(`app/pamela.py`) is untouched; no patch path exists in the API or in any agent tool.

## D. Real patch evidence

Applied run (`lab/patch/audit/20261112T192721Z-fixture-eligible-medium.json`):

```
decision: eligible
before_sha256: 22b7a074…18083a
after_sha256:  a4143b8c…2f5f1   (= manifest)
checks: health "200 ok" | attack_blocked "400 refused: payload not in the lab allowlist"
        | safe_endpoint "200 ok 127.0.0.1"
result: applied
```

Rolled-back run (`…20261112T192826Z…`, `--force-failure`):

```
result: rolled_back
rollback_check: {"vulnerable_again": true, "value": "200 LAB_RCE_OK"}
```

Denials:

```
incident-file eligible, no --enable   → {"allowed": false, "reason": "auto_patch_disabled"}
incident-file denied_high, --enable   → {"allowed": false, "reason": "needs_human"}
real T2 incident id, --enable         → {"allowed": false, "reason": "not_decided"}
```

The real-incident denial is the important honest result: without a completed pipeline the
policy refuses to patch. The allowed-path run uses `fixtures/eligible_medium.json`, which
is labelled as a policy fixture in the audit file.

## E. Acceptance matrix

| Requirement | Result | Evidence |
|---|---|---|
| Low eligible patch PASS | PASS | unit |
| Medium eligible patch PASS | PASS | unit + real clone apply |
| High/Critical denied | PASS | unit (parametrized) + CLI `needs_human` |
| Unsupported template denied | PASS | unit `unsupported_template` |
| Unknown/partial evidence denied | PASS | unit `unverified_evidence` |
| Unmanaged target denied | PASS | unit `unmanaged_target` |
| Malformed/forged request denied | PASS | no `--enable`, tampered hash, image mismatch |
| Failed verification → rollback | PASS | forced-failure audit, exploit works again |
| T1/T2/T4–T9 unchanged | PASS | `lab/verify_lab.py` 10/10 |
| No autonomous containment | PASS | decision/PAMELA/revert need operator token |
| Real incident end-to-end auto-patch | **BLOCKED** | pipeline not done (GATER) |
| Patch applied to canonical service | **NOT IMPLEMENTED** | deliberate: clone keeps lab reproducible |

## F. Regression

- `cd backend && uv run pytest -q` → **287 passed**
- `uv run ruff check . ../shipper` → clean
- `python3 lab/verify_lab.py` → 10/10 PASS (T1, T2, T5, T6, T7, T8, T4×3, T9)
- Frontend untouched (last lint/build clean, Phase 3).

## G. Security risk summary

| Risk | Status |
|---|---|
| LLM executes patches | No path exists |
| Untrusted template / tampered hash | Denied before clone |
| Wrong image/target | Denied by image identity |
| Patch breaks app | Health/exploit/safe checks; rollback restores snapshot |
| Patch persists into lab scenarios | Clone is removed; canonical service untouched |
| Patch status in dashboard | Not implemented (audit files only) |
| Containment triggered by patch flow | No; separate code and operator token |
| Clone escapes lab | `--network none`, cap-drop ALL, no-new-privileges, 256 MB |
| Rollback of a production deploy | Out of scope; clone-only demonstration |

## H. Demo procedure

```sh
# 0. lab up (Phase 2/3)
docker compose up -d --build
docker compose -f lab/docker-compose.yml --env-file .env up -d --build

# 1. show denial: high severity / disabled
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/denied_high.json --enable
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json

# 2. dry run and apply
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable --dry-run
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable

# 3. rollback proof
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable --force-failure

# 4. show the honest blocker with a live incident
python3 lab/patch/apply.py --incident <T2 incident id> --enable   # not_decided
```

Talking points: policy engine is deterministic and unit-tested; patch content is a
reviewed file, never model output; every run leaves an audit file; failure restores the
vulnerable behaviour and proves it.

## I. Rubric alignment

- **Relevance**: bounded, auditable remediation rather than autonomous shell.
- **Innovation**: deterministic eligibility + supply-chain hash + clone-apply-verify-rollback.
- **Functionality**: real apply and rollback evidence, 287 tests, 10 lab checks.
- **Feasibility**: operator tool, no new service, no Docker socket exposed to backend.
- **Documentation**: policy, report, audit trail, demo commands.

## J. Remaining blockers

1. **Live LLM** — real incidents stay `not_decided`, so the auto-patch path cannot be
   demonstrated end-to-end from detection to patch without GATER.
2. **Canonical-service patching** — deliberately not implemented; clone-only.
3. **Dashboard/DB patch status** — files only.
4. **Only one patch template** (command injection), no dependency patches.
5. **No staging/monitoring window** — health + exploit + safe checks only.

## K. Git summary

Local commits on `hardening/kartika-mvp-sync` (no push, no merge): policy engine + tests,
lab patch executor/template/evidence, documentation.

## L. Decision

**CONDITIONAL GO** for a controlled, lab-only auto-patch demonstration with real apply and
rollback evidence.
**NO-GO** for production auto-patching, real-incident end-to-end auto-patch without GATER,
or any claim that a patch was applied to the canonical service.
