"""The application's restricted database login (ADR 0026): what it can and cannot do."""

import secrets
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.storage import dbroles

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def app_engine(test_engine):
    """A real login with exactly the application's privileges on the test database."""
    role = f"cs_app_test_{uuid.uuid4().hex[:8]}"
    password = secrets.token_urlsafe(24)
    with test_engine.begin() as conn:
        dbroles.apply(conn, role, password, test_engine.url.database)
        # Re-applying is safe (it runs after every migration).
        dbroles.apply(conn, role, password, test_engine.url.database)
    engine = create_engine(test_engine.url.set(username=role, password=password))
    yield engine
    engine.dispose()
    with test_engine.begin() as conn:
        conn.execute(text(f'DROP OWNED BY "{role}"'))
        conn.execute(text(f'DROP ROLE "{role}"'))


def _refused(engine, statement: str) -> bool:
    with engine.connect() as conn:
        try:
            conn.execute(text(statement))
        except (ProgrammingError, DBAPIError) as exc:
            conn.rollback()
            return "permission denied" in str(exc) or "must be owner" in str(exc)
        conn.rollback()
        return False


def test_the_application_login_can_read_and_write_ordinary_rows(app_engine):
    with app_engine.connect() as conn:
        conn.execute(
            text("INSERT INTO clients (id, name, created_at) VALUES (:id, :n, now())"),
            {"id": uuid.uuid4(), "n": f"Role test {uuid.uuid4().hex[:6]}"},
        )
        assert conn.execute(text("SELECT count(*) FROM clients")).scalar() >= 1
        conn.execute(text("SELECT pg_advisory_xact_lock(1)"))
        conn.rollback()


@pytest.mark.parametrize(
    "statement",
    [
        # Cannot switch off the triggers that protect history.
        "ALTER TABLE audit_events DISABLE TRIGGER ALL",
        "ALTER TABLE scan_runs DISABLE TRIGGER ALL",
        "SET session_replication_role = replica",
        # Cannot change or remove history rows at all.
        "DELETE FROM audit_events",
        "UPDATE audit_events SET outcome = 'x'",
        "DELETE FROM assessment_finalizations",
        "DELETE FROM scan_runs",
        "DELETE FROM findings",
        "DELETE FROM finding_review_events",
        "TRUNCATE audit_events",
        # Cannot change the schema or migration state.
        "DROP TABLE clients",
        "CREATE TABLE sneaky (id int)",
        "DELETE FROM alembic_version",
        "CREATE ROLE helper",
    ],
)
def test_the_application_login_cannot_tamper(app_engine, statement):
    assert _refused(app_engine, statement), statement
