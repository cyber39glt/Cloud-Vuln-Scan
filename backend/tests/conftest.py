from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from moto import mock_aws
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import build_engine, get_engine
from app.main import app

ALEMBIC_INI = Path(__file__).parents[1] / "alembic.ini"


@pytest.fixture(autouse=True)
def _reset_login_rate_limit():
    """The login limiter is per process; each test starts with a clean slate."""
    from app.auth.ratelimit import login_limiter

    login_limiter.reset()
    yield
    login_limiter.reset()


@pytest.fixture
def client():
    # "localhost": the API only answers to allowed host names (DNS-rebinding defence).
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ------------------------------------------------------------------ database
#
# A separate database `<POSTGRES_DB>_test` is created and migrated with Alembic, so
# tests never touch development data.


@pytest.fixture(scope="session")
def test_engine():
    settings = Settings(_env_file=None)
    test_db = f"{settings.postgres_db}_test"
    admin = create_engine(settings.database_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{test_db}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{test_db}"'))

    engine = create_engine(settings.database_url.set(database=test_db))
    config = Config(str(ALEMBIC_INI))
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.upgrade(config, "head")
    yield engine

    engine.dispose()
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{test_db}" WITH (FORCE)'))
    admin.dispose()


@pytest.fixture
def db(test_engine):
    connection = test_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def unreachable_database():
    """Point the app at a port where nothing listens, so connections are refused.

    This exercises the real failure path without mocking the database driver.
    """
    engine = build_engine(
        "postgresql+psycopg://nobody:not-a-real-password@127.0.0.1:1/none",
        connect_timeout_seconds=1,
    )
    app.dependency_overrides[get_engine] = lambda: engine
    yield
    engine.dispose()


@pytest.fixture
def settings() -> Settings:
    """Default settings, ignoring any local .env file."""
    return Settings(_env_file=None)


@pytest.fixture
def aws(monkeypatch):
    """Fake platform credentials + simulated AWS (moto). No real AWS is contacted."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    _simulate_bucket_policy_status(monkeypatch)
    with mock_aws():
        yield


def _simulate_bucket_policy_status(monkeypatch) -> None:
    """moto does not compute PolicyStatus.IsPublic (AWS's own policy analysis), and the
    collector rightly refuses to guess without it. Fill it in AFTER the real call (so
    the read-only guard still runs): public = an Allow statement for Principal "*"
    without conditions. Tests needing other answers register their own handlers."""
    import json

    from botocore.client import BaseClient
    from moto.s3.models import s3_backends

    original = BaseClient._make_api_call

    def make_api_call(self, operation_name, api_params):
        response = original(self, operation_name, api_params)
        if operation_name == "GetBucketPolicyStatus" and "IsPublic" not in response.get(
            "PolicyStatus", {}
        ):
            [bucket] = [
                backend["aws"].buckets[api_params["Bucket"]]
                for backend in s3_backends.values()
                if api_params["Bucket"] in backend["aws"].buckets
            ]
            statements = json.loads(bucket.policy or b"{}").get("Statement", [])
            public = any(
                s.get("Effect") == "Allow"
                and s.get("Principal") in ("*", {"AWS": "*"})
                and not s.get("Condition")
                for s in statements
            )
            response = {**response, "PolicyStatus": {"IsPublic": public}}
        return response

    monkeypatch.setattr(BaseClient, "_make_api_call", make_api_call)


# ------------------------------------------------------------------ API clients


@pytest.fixture
def http(db, monkeypatch):
    """An API client (not logged in) whose requests run inside the test transaction."""
    from sqlalchemy.orm import sessionmaker

    from app.api import deps
    from app.core.config import get_settings
    from tests.auth_helpers import plain_http_settings

    factory = sessionmaker(
        bind=db.connection(), join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    monkeypatch.setattr(deps, "get_sessionmaker", lambda: factory)
    app.dependency_overrides[get_settings] = plain_http_settings
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin(db):
    """An administrator with MFA set up: (user, totp_secret)."""
    from tests.auth_helpers import make_user

    return make_user(db, "admin@subtletech.test")


@pytest.fixture
def api(http, db, admin):
    """An API client logged in as the administrator."""
    from tests.auth_helpers import login

    login(http, db, *admin)
    return http
