"""Alembic environment: connects using the application's own settings, so the
database URL and password come from the environment, never from a file."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from app.core.config import get_settings
from app.storage.models import Base

config = context.config
if config.config_file_name is not None:
    # Keep loggers the application already configured (e.g. when tests run migrations).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_online() -> None:
    # Tests pass an existing connection (to migrate a separate test database).
    connection = config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = create_engine(get_settings().database_url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Offline (SQL script) migrations are not supported; run against a database.")
run_migrations_online()
