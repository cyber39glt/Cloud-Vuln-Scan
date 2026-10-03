import pytest


def test_liveness_returns_ok(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_unavailable_database_without_details(client, unreachable_database):
    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "checks": {"database": "unavailable"}}
    # The unauthenticated response must not leak connection details.
    assert "127.0.0.1" not in response.text
    assert "nobody" not in response.text


@pytest.mark.integration
def test_readiness_with_real_database(client):
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok"}}
