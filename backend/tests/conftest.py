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
