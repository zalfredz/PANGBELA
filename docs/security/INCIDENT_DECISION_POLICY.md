# Incident decision and response policy (v1, MVP)

This is the policy the code is allowed to enforce. Where code and policy disagree, the
gap is listed in `docs/audit/BASELINE_RECONCILIATION.md`; it is not silently ignored.

## 1. Who decides

1. Code computes facts from stored evidence (`compute_facts`).
2. Code computes the highest status the facts allow (`max_status`).
3. Agents may propose any status. `rules_gate` records a difference as `rules_conflict`
   and keeps the code's status.
4. Only the rules node writes `incidents.status` and `severity`.
5. The LLM cannot downgrade to benign. Cited evidence ids prove an event exists, not
   that the model's interpretation is correct.
6. A benign verdict must come from deterministic facts. Today that is only
   `brute_force` below `BRUTE_FORCE_MIN_FAILURES`; there is no trusted-benign source for
   RCE, so an RCE attempt is never benign.

Statuses: `benign` < `suspected` < `attempted` < `confirmed`.
Verification states are separate from status: `verified`, `partially_verified`,
`insufficient_telemetry`. Missing telemetry never reads as "the attack failed".
`confidence` is a documented heuristic (source coverage minus penalties), not a
probability.

## 2. RCE evidence requirements

| Level | Required evidence |
|---|---|
| `suspected` | a classified RCE alert |
| `attempted` | alert **and** a matching request in the access log (path match) |
| `confirmed` | the two above, **and** a process event whose parent is the configured web server **and** whose `request_id` matches the request inside −2 s/+10 s |

`WEB_SERVER_EXES` empty means RCE can never be confirmed. `RCE_SIGNATURE_IDS` must be
validated against the lab's own Suricata rules before it is set.

**Known gap (P0).** The third row proves *linkage*, not *lack of authorization*. A web
application that legitimately spawns the same child with a request id would also match.
The MVP must not claim "unauthorized execution" until the lab emits an authorization
fact (for example `process_log.fields.authorized=false` from the application's own
policy) or an allowlist of approved child executables per endpoint. Until then, treat
`confirmed` as "request-linked execution" and say so in the demo.

Negative outcomes that must hold in the lab matrix:

- failed exploit attempt → `attempted`
- ambiguous request/process relationship → `partially_verified`, never `confirmed`
- host telemetry unavailable → `insufficient_telemetry`, never `confirmed`
- HTTP 200 alone is never proof.

## 3. Brute-force evidence requirements

`BRUTE_FORCE_MIN_FAILURES` (10) inside `BRUTE_FORCE_WINDOW_SECONDS` (120) is an MVP test
parameter, not a universal threshold.

| Facts | Status |
|---|---|
| failures below threshold, or ordinary mistakes | `benign` |
| threshold reached, no success | `attempted` |
| threshold reached, success marked `authorized=true` | `attempted` (legitimate login) |
| threshold reached, success marked `authorized=false` | `confirmed` |
| threshold reached, success with no `authorized` field | `attempted` + `partially_verified` |
| auth log unavailable | `insufficient_telemetry` |

Limitations: grouping is per source IP. Shared NAT and multiple users on one address can
merge unrelated logins; the verdict stays `attempted` in that case because authorization
is unmarked. Ground truth for scenarios lives with the scenario runner, never in prompts.

## 4. Severity (v1, deterministic)

| Attack | Status | Severity |
|---|---|---|
| rce | confirmed | critical |
| rce | attempted | medium |
| rce | suspected | low |
| brute_force | confirmed | high |
| brute_force | attempted | medium |
| brute_force | suspected | low |
| any | benign | none |

Asset criticality and measured impact are not in v1. Adding them changes this table, not
the status logic, and requires a version bump.

## 5. Response policy (PAMELA)

PAMELA only records actions for the lab to pull from `GET /enforcement`; it never touches
a firewall, account, or host itself. Actions: `block_ip`, `monitor`, `reset_password`,
`isolate_host`. Targets come from the incident record, never from agent-written text.
`PROTECTED_IPS` are never blocked.

| Severity | Automatic (PAMELA) | Manual | Response |
|---|---|---|---|
| none | no | no | monitor |
| low | yes, if a code target exists | yes | controlled remediation |
| medium | yes, if a code target exists | yes | controlled remediation |
| high | **no** | required | alert + human response |
| critical | **no** | required | escalation + human containment |

Patching (`patch_endpoint`) is **not executable** in this MVP: it is always a manual
task, at every severity. The agreed Low/Medium conditional auto-patch flow (allowlisted
template, dry run, staging test, health check, rollback, audit) is not implemented and
must not be described as working. Destructive actions (host isolation, password reset,
IP blocking) stay human-approved until a separate policy is tested.

## 6. Operator authentication

Every `POST /recommendations/{id}/decision`, `POST /recommendations/{id}/pamela`, and
`POST /actions/{id}/revert` requires `X-Operator-Token`.

- Tokens come from `OPERATOR_TOKENS` (`name:token` pairs, token ≥ 32 chars).
- The recorded `decided_by` / `reverted_by` is the name mapped to the token. A
  `decided_by` field in the body is ignored.
- No operators configured → `503 operators_not_configured` (fail closed, no anonymous
  approvals).
- Wrong or missing token → `401 invalid_operator_token`.
- `PAMELA` cannot be used as an operator name.
- `GET /enforcement` uses `X-Enforcement-Token`, a different secret from both the LLM key
  and the operator tokens.

Lab-only shortcut: the dashboard keeps the token in `sessionStorage`. That is not a
login system; before any non-lab deployment it needs a server-side session and per-role
permissions.

## 7. Lab requirements for P0 acceptance

The repository has no lab yet. Before T1–T9 can pass, the lab must provide:

1. a vulnerable app with a harmless command-injection marker and a safe endpoint;
2. an auth service with synthetic accounts and an `authorized` fact it controls, not the
   attacker;
3. Suricata observing the real traffic path, with rule ids configured in
   `RCE_SIGNATURE_IDS` / `BRUTE_FORCE_SIGNATURE_IDS`;
4. process telemetry with parent/child, request id, container/host identity;
5. ground-truth manifests kept outside the evidence the agents read.

Until then, the only evidence-backed claims are the unit and integration tests listed in
the audit file.
