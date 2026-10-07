import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app.core.config import Settings
from app.core.database import build_engine, get_engine
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


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
    with mock_aws():
        yield
