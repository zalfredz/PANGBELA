"""Scenario results (spec section 8): compares what happened with test_cases.

Scenarios are run by the cybersec team's attack scripts, not by this API. Each one
attacks from its own source IP, so a test case matches incidents by src_ip.
"""

from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from sqlalchemy import text

from app import db

router = APIRouter()


@router.get("/tests/results")
def test_results() -> list[dict]:
    # The latest incident from the scenario's IP is the one compared. Its status only
    # counts once the pipeline is done; before that it is the untouched default.
    sql = """
        SELECT tc.id AS test_case, i.id AS incident_id, tc.expected_status,
               CASE WHEN i.pipeline_state = 'done' THEN i.status END AS actual_status
        FROM test_cases tc
        LEFT JOIN LATERAL (
            SELECT id, status, pipeline_state FROM incidents
            WHERE src_ip = tc.src_ip ORDER BY created_at DESC LIMIT 1
        ) i ON true
        ORDER BY tc.id
    """
    with db.engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(text(sql)).mappings()]
    for r in rows:
        r["match"] = r["actual_status"] is not None and r["actual_status"] == r["expected_status"]
    return jsonable_encoder(rows)
