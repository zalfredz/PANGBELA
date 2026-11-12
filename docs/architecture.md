# PANGBELA architecture (MVP)

AI-assisted SOC for two attack types: web command injection (RCE) and brute-force
authentication. Code decides, agents explain, a human authorizes response.

## Components

```
lab (isolated, internal network, no published ports)
  app        vulnerable/safe endpoints; writes access.log + process.log; real /proc reads
  auth       synthetic users; authorized = source CIDR policy; writes auth.log
             and posts X-Auth-Ingest-Token to the backend
  suricata   joins the app network namespace; writes eve.json
  runner     one scenario per run; maintenance signs approved operations
        │ volumes: ai-soc-lab-logs, ai-soc-suricata-logs
        ▼
backend (FastAPI, PostgreSQL)
  ingest/suricata  X-Ingest-Token        → alerts → incident grouping
  ingest/auth      X-Auth-Ingest-Token   → auth_events (+ producer) → brute-force incident
  early warning    rules only, 5 s loop, no LLM → provisional_status, SSE warning
  pipeline         LangGraph: detection → investigation → forensics → decision
                   OpenAI-compatible client (GATER baseline); citation check
  rules gate       compute_facts + max_status are the only writers of status/severity
  PAMELA           containment rows for the lab to pull; operator-token gated
  patch policy     pure eligibility engine; no execution path
  patch_runs       read-only records posted by the operator executor
        ▲
dashboard (Next.js) read-only truth + operator actions with X-Operator-Token
```

## Trust boundaries

| Boundary | Mechanism |
|---|---|
| Lab → backend alerts | `X-Ingest-Token`; only alert events parsed |
| Auth producer → backend | separate `X-Auth-Ingest-Token`; producer recorded per row |
| Log content → agents | attacker text only inside `<untrusted_data>`; never in system prompt |
| Agent proposal → verdict | `rules_gate` clamps to `max_status`; disagreement recorded |
| Human → response endpoints | `X-Operator-Token`; server-derived name; fail-closed 503 |
| Backend → shell/patch | none: no subprocess, no Docker socket in `backend/app` |
| Operator → lab patch | host CLI only; allowlisted template, hash, managed image, clone |
| Lab ↔ Internet/host | `internal` network, no published ports, cap-drop, memory caps |

## Verdict model

`benign < suspected < attempted < confirmed`, plus verification
(`verified | partially_verified | insufficient_telemetry`). Evidence coverage and
confidence are labelled heuristics. RCE confirmation needs a linked web-server child with
`authorized: false`; brute-force confirmation needs a success with `authorized: false`
after the failure threshold. Missing telemetry degrades, never confirms.

A signed maintenance operation (HMAC + nonce + window) that triggers the IDS rule and
executes an allowed child becomes `benign` deterministically (T4).

## Data flow for a demo

1. Runner attacks the lab; Suricata + app write telemetry.
2. Shipper posts alerts; the rules loop computes a provisional verdict within ~1–4 s.
3. On a configured LLM, the pipeline investigates and writes the final report (currently
   BLOCKED without GATER credits).
4. The dashboard shows evidence, verdict, uncertainty, recommendations, patch history.
5. Operators can approve/reject containment; the lab pulls actions from `/enforcement`.
6. An operator can run the patch CLI against a disposable clone; results are audited and
   visible read-only in the dashboard.

## Deployment shape

Docker Compose: `postgres + backend + shipper`; `lab/docker-compose.yml` attaches to the
same named volumes and network. Configuration is environment-based; migrations run
before the backend starts. No cloud dependency, no inbound public surface.

## Deliberate limits

- Process telemetry is application-instrumented (documented Falco fallback), not EDR.
- Patch executor targets a disposable clone, not the canonical lab service.
- Patch status is audit files + a read-only table; no dashboard trigger button.
- Only two attack types; T3 reconnaissance and live-LLM prompt injection are blocked.
