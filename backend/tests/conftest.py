"""Tests run against the Postgres at DATABASE_URL, inside a throwaway schema that is
dropped afterwards, so dev data is never read or modified."""

import uuid

import pytest
from sqlalchemy import create_engine, text

from app import db
from app.config import settings
from scripts.migrate import migrate


@pytest.fixture(scope="session")
def test_engine():
    schema = f"test_{uuid.uuid4().hex[:8]}"
    admin = create_engine(settings.DATABASE_URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    # gen_random_uuid lives in pg_catalog, so search_path needs only the test schema.
    engine = create_engine(
        settings.DATABASE_URL, connect_args={"options": f"-csearch_path={schema}"}
    )
    with engine.begin() as conn:
        migrate(conn)
    yield engine
    engine.dispose()
    with admin.begin() as conn:
        conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    admin.dispose()


@pytest.fixture
def engine(test_engine, monkeypatch):
    monkeypatch.setattr(db, "engine", test_engine)
    yield test_engine
    with test_engine.begin() as conn:
        conn.execute(text("TRUNCATE incidents, auth_events, lab_status CASCADE"))
