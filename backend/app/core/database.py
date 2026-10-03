"""Database connection management.

M0 only needs to prove the database is reachable. Tables, models and migrations
arrive in a later milestone and will build on this engine.
"""

from functools import lru_cache

from sqlalchemy import URL, Engine, create_engine, text

from app.core.config import get_settings


def build_engine(url: URL | str, connect_timeout_seconds: int) -> Engine:
    return create_engine(
        url,
        # Test each pooled connection before use, so a restarted database
        # does not cause errors on the first request afterwards.
        pool_pre_ping=True,
        connect_args={"connect_timeout": connect_timeout_seconds},
    )


@lru_cache
def get_engine() -> Engine:
    """One shared connection pool per process, created on first use."""
    settings = get_settings()
    return build_engine(settings.database_url, settings.db_connect_timeout_seconds)


def check_database(engine: Engine) -> None:
    """Run a trivial query; raises if the database is unreachable."""
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
