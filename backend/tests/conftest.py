import pytest
from fastapi.testclient import TestClient

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
