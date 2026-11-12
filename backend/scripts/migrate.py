"""Apply backend/migrations/*.sql in filename order, each file once.

Applied files are recorded in schema_migrations so running this twice is safe.
"""

import sys
from pathlib import Path

from sqlalchemy import Connection, text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import engine  # noqa: E402

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def migrate(conn: Connection) -> list[str]:
    """Apply pending migrations on conn and return the names applied. Caller commits."""
    conn.execute(
        text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " name text PRIMARY KEY,"
            " applied_at timestamptz NOT NULL DEFAULT now())"
        )
    )
    done = set(conn.execute(text("SELECT name FROM schema_migrations")).scalars())
    applied = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if path.name in done:
            continue
        # exec_driver_sql sends the file as-is; psycopg runs multi-statement text
        # when no parameters are bound.
        conn.exec_driver_sql(path.read_text())
        conn.execute(text("INSERT INTO schema_migrations (name) VALUES (:n)"), {"n": path.name})
        applied.append(path.name)
    return applied


def main() -> None:
    with engine.begin() as conn:
        applied = migrate(conn)
        tables = (
            conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables"
                    " WHERE table_schema = current_schema() AND table_name <> 'schema_migrations'"
                    " ORDER BY table_name"
                )
            )
            .scalars()
            .all()
        )
    print(f"applied: {applied or 'nothing, already up to date'}")
    print(f"tables ({len(tables)}): {', '.join(tables)}")


if __name__ == "__main__":
    main()
