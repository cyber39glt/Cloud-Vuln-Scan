"""The application's restricted database login (ADR 0026).

The tables are owned by the migration login. The API and the worker connect as a
separate login that may only read and write rows: it cannot change table structure,
cannot disable the triggers that protect stored results and the audit log, and may
not delete or change rows in the history tables at all. Even someone who obtains
the application's database credentials cannot quietly rewrite results or the audit
trail.

    python -m app.storage.dbroles     (run with the OWNER login, after migrations)

creates the application login if needed, sets its password and (re)applies the
privileges below. It is idempotent: run it after every migration.
"""

import sys

from psycopg import sql
from sqlalchemy import Connection, create_engine, text

from app.core.config import Settings, get_settings

# History: rows are added, never changed or removed by the application.
APPEND_ONLY_TABLES = (
    "audit_events",
    "scan_runs",
    "findings",
    "finding_review_events",
    "assessment_finalizations",
)


def _ident(conn: Connection, name: str) -> str:
    return sql.Identifier(name).as_string(conn.connection.dbapi_connection)


def _literal(conn: Connection, value: str) -> str:
    return sql.Literal(value).as_string(conn.connection.dbapi_connection)


def apply(conn: Connection, role: str, password: str, database: str) -> None:
    """Create or update `role` with exactly the application's privileges."""
    r, pw, db = _ident(conn, role), _literal(conn, password), _ident(conn, database)
    attributes = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).scalar()
    verb = "ALTER" if exists else "CREATE"
    conn.execute(text(f"{verb} ROLE {r} WITH {attributes} PASSWORD {pw}"))

    for statement in (
        f"GRANT CONNECT ON DATABASE {db} TO {r}",
        f"GRANT USAGE ON SCHEMA public TO {r}",
        f"REVOKE CREATE ON SCHEMA public FROM {r}",
        f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {r}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {r}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {r}",
        # History tables: insert and read only.
        f"REVOKE UPDATE, DELETE ON {', '.join(APPEND_ONLY_TABLES)} FROM {r}",
        # Migration bookkeeping: read only.
        f"REVOKE INSERT, UPDATE, DELETE ON alembic_version FROM {r}",
    ):
        conn.execute(text(statement))


def main() -> int:
    settings: Settings = get_settings()
    if not settings.postgres_owner_user or settings.postgres_owner_user == settings.postgres_user:
        print(
            "Set POSTGRES_OWNER_USER (the migration login) to a different login than "
            "POSTGRES_USER (the application login)."
        )
        return 1
    engine = create_engine(settings.owner_database_url)
    with engine.begin() as conn:
        apply(
            conn,
            settings.postgres_user,
            settings.postgres_password.get_secret_value(),
            settings.postgres_db,
        )
    engine.dispose()
    print(f"Application login '{settings.postgres_user}' has the restricted privileges.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
