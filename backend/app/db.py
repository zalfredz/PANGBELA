from sqlalchemy import create_engine

from app.config import settings

# pool_pre_ping: Supabase drops idle connections, so check before reuse.
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)


def connect():
    # Reads the module global at call time so tests can swap in their own engine.
    return engine.connect()
