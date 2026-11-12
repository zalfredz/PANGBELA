# ai-soc

Suricata alerts go in, LLM agents investigate them against lab logs, and a rules gate decides the final status. Spec: `docs/build-spec.md`. Rules for Claude Code: `CLAUDE.md`.

Current state: M0 to M4 are built and their checks pass with GATER (`solar-pro4-v2`). M5 and M7 wait on lab samples from the cybersec team.

## Requirements

- Docker with Compose v2 (Docker Desktop, OrbStack or Colima)
- [uv](https://docs.astral.sh/uv/) for local backend work; it installs Python 3.12 itself

## Run

```sh
cp .env.example .env        # fill LLM_* and INGEST_TOKEN (openssl rand -hex 32); blank values use backend/app/config.py defaults
docker compose up -d --build
docker compose exec backend uv run --no-sync python scripts/migrate.py
curl localhost:8000/health  # {"db":"ok","llm_configured":true} once LLM_* is set
```

Inside compose the backend always talks to the `postgres` service; `DATABASE_URL` in `.env` is used when running the backend on the host.

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

## LLM checks (need LLM_BASE_URL, LLM_API_KEY, LLM_MODEL in .env)

```sh
cd backend
uv run python scripts/check_llm.py            # M2: provider check, run once per provider
uv run python scripts/run_fixture_pipeline.py # M3: one full pipeline run on the fixture incident
```

Both send only fixture text from `backend/tests/fixtures/` to the provider. The fixture run uses a throwaway schema, so nothing lands in the dev database.
