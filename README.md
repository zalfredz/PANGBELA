# ai-soc

Suricata alerts go in, LLM agents investigate them against lab logs, and a rules gate decides the final status. Spec: `docs/build-spec.md`. Rules for Claude Code: `CLAUDE.md`.

Current state: M0 to M4 are built and their checks pass with GATER (`solar-pro4-v2`). M5 and M7 wait on lab samples from the cybersec team.

## Requirements

- Docker with Compose v2 (Docker Desktop, OrbStack or Colima)
- [uv](https://docs.astral.sh/uv/) for local backend work; it installs Python 3.12 itself

## Run

```sh
cp .env.example .env        # fill LLM_*, INGEST_TOKEN, AUTH_INGEST_TOKEN, OPERATOR_TOKENS (openssl rand -hex 32); blank values use backend/app/config.py defaults
# Schema before the backend: on a fresh database the backend exits at startup while
# `incidents` is missing. `run` starts postgres and exits when the migration is done.
docker compose run --rm backend uv run --no-sync python scripts/migrate.py
docker compose up -d --build
curl localhost:8000/health  # {"db":"ok","llm_configured":true} once LLM_* is set
```

Inside compose the backend always talks to the `postgres` service; `DATABASE_URL` in `.env` is used when running the backend on the host.

Approving, rejecting, reverting, or handing an action to PAMELA needs an operator token:
set `OPERATOR_TOKENS=name:<openssl rand -hex 32>` in `.env` and enter the same token in
the dashboard's "Token operator" field (`X-Operator-Token`). With no operators configured
those endpoints return 503 on purpose. Policy and evidence requirements:
`docs/security/INCIDENT_DECISION_POLICY.md`; current gaps:
`docs/audit/BASELINE_RECONCILIATION.md`.

How an alert flows: the lab's Suricata writes `eve.json` into the `ai-soc-suricata-logs` volume, the `shipper` service posts alert lines to `POST /ingest/suricata`, and the backend groups them into incidents. Once an incident has been quiet for `PIPELINE_DEBOUNCE_SECONDS`, a background loop runs the agent pipeline on it, one incident at a time. Web, auth and process logs are read from the `ai-soc-lab-logs` volume, mounted at `/lab-logs`.

Watch a run live:

```sh
curl -N localhost:8000/incidents/<id>/stream
```

Replay a capture from `samples/` (posts every alert in the file, then exits):

```sh
EVE_JSON_PATH=samples/T1/eve.json INGEST_URL=http://localhost:8000/ingest/suricata \
INGEST_TOKEN=<from .env> python3 shipper/shipper.py --once
```

## Backend on the host

Tests need the compose Postgres running. They work in a throwaway schema and never touch dev data.

```sh
cd backend
uv sync
uv run python scripts/migrate.py
uv run pytest
uv run ruff check . ../shipper
uv run uvicorn app.main:app --reload
```

## Isolated lab (RCE + brute force)

`lab/` runs a deliberately vulnerable app, an auth service, Suricata and a scenario
runner on an internal Docker network, writing into the same volumes as the main stack.

```sh
docker compose up -d --build
docker compose -f lab/docker-compose.yml --env-file .env up -d --build
python3 lab/verify_lab.py     # real traffic, deterministic checks, no LLM
```

The lab also needs `LAB_APPROVAL_SECRET` (signed maintenance operations, T4) and
`AUTH_INGEST_TOKEN` (login events). Setup, reset and safety notes: `lab/README.md`.
Results: `docs/testing/PHASE2_REAL_LAB_REPORT.md`,
`docs/testing/PHASE3_VALIDATION_REPORT.md`.

## Controlled patch demo (Phase 4, lab clone only)

```sh
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json           # denied by default
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable --dry-run
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable --force-failure
```

Policy, eligibility and limits: `docs/security/PAMELA_PATCH_POLICY.md`.
Evidence and matrix: `docs/testing/PHASE4_PATCH_REPORT.md`.

## LLM checks (need LLM_BASE_URL, LLM_API_KEY, LLM_MODEL in .env)

```sh
cd backend
uv run python scripts/check_llm.py            # M2: provider check, run once per provider
uv run python scripts/run_fixture_pipeline.py # M3: one full pipeline run on the fixture incident
```

Both send only fixture text from `backend/tests/fixtures/` to the provider. The fixture run uses a throwaway schema, so nothing lands in the dev database.
