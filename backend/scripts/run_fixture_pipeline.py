"""M3 check: one full pipeline run on the fixture incident with the real LLM.

    uv run python scripts/run_fixture_pipeline.py

Runs in a throwaway Postgres schema that is dropped afterwards, so the hand-written
fixture never lands in the dev database or the dashboard. Sends only the fixture
alert and fixture access log to the provider.
"""

import json
import sys
import uuid
from pathlib import Path

from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db  # noqa: E402
from app.config import settings  # noqa: E402
from app.graph.pipeline import PipelineFailed, run_pipeline  # noqa: E402
from app.ingest.eve_parser import parse_alert  # noqa: E402
from app.ingest.grouping import group_alert  # noqa: E402
from scripts.migrate import migrate  # noqa: E402
from tests.fixtures.eve_alerts import alert  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def main() -> int:
    if not settings.llm_configured:
        print("LLM_BASE_URL, LLM_API_KEY and LLM_MODEL must all be set (see .env.example).")
        return 2

    cfg = settings.model_copy(
        update={
            "ACCESS_LOG_PATH": str(FIXTURES / "access_rce.jsonl"),
            "AUTH_LOG_PATH": "/nonexistent/auth.log",
            "PROCESS_LOG_PATH": "/nonexistent/process.log",
        }
    )
    schema = f"fixture_{uuid.uuid4().hex[:8]}"
    admin = create_engine(settings.DATABASE_URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        settings.DATABASE_URL, connect_args={"options": f"-csearch_path={schema}"}
    )
    db.engine = engine
    try:
        with engine.begin() as conn:
            migrate(conn)
            incident_id, _ = group_alert(
                conn, parse_alert(alert("2026-11-11T02:00:00.000000+0000")), 600
            )
        print(f"fixture incident {incident_id} (schema {schema}), model {settings.LLM_MODEL}\n")
        failed = None
        try:
            run_pipeline(incident_id, cfg=cfg)
        except PipelineFailed as e:
            failed = e

        with engine.connect() as conn:
            for r in conn.execute(
                text(
                    "SELECT agent, round, status, latency_ms, cited_evidence_ids, rules_conflict,"
                    " error, output_json FROM agent_runs ORDER BY started_at"
                )
            ).mappings():
                print(
                    f"== {r['agent']} round {r['round']}: {r['status']}"
                    f" ({r['latency_ms']} ms) cited={r['cited_evidence_ids']}"
                )
                if r["rules_conflict"]:
                    print(f"   rules_conflict: {r['rules_conflict']}")
                if r["error"]:
                    print(f"   error: {r['error']}")
                if r["output_json"] is not None:
                    print(json.dumps(r["output_json"], indent=2))
            inc = (
                conn.execute(
                    text(
                        "SELECT attack_type, status, severity, confidence, scanner_likely,"
                        " pipeline_state, summary FROM incidents"
                    )
                )
                .mappings()
                .one()
            )
            print(f"\n== verdict: {dict(inc)}")
            total = conn.execute(
                text(
                    "SELECT EXTRACT(EPOCH FROM max(finished_at) - min(started_at)) FROM agent_runs"
                )
            ).scalar()
            print(f"== pipeline time: {float(total):.1f} s")
            for r in conn.execute(text("SELECT action, target, reason FROM recommendations")):
                print(f"   recommendation: {r.action} {r.target}: {r.reason}")
        if failed:
            print(f"\npipeline FAILED at {failed.agent}: {failed.error}")
            return 1
        return 0
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


if __name__ == "__main__":
    sys.exit(main())
