"""The data API against the test database, logged in as an administrator: behaviour,
client isolation and the HTTP-level protections. No cloud is contacted: scans are only
queued here. Authentication and roles are tested in test_auth.py."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory
from app.storage import repository as repo

pytestmark = pytest.mark.integration

TENANT = "22222222-2222-2222-2222-222222222222"
SUB = "11111111-1111-1111-1111-111111111111"


def _client(api, name="Acme Ltd") -> str:
    response = api.post("/api/v1/clients", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _aws_assessment(api, client_id, account="111122223333", name="Q1 review") -> tuple[str, str]:
    connection = api.post(
        f"/api/v1/clients/{client_id}/connections/aws", json={"account_id": account}
    ).json()["connection"]
    response = api.post(
        f"/api/v1/clients/{client_id}/assessments",
        json={"connection_id": connection["id"], "name": name},
    )
    assert response.status_code == 201, response.text
    return connection["id"], response.json()["id"]


# ------------------------------------------------------------------ clients + connections


def test_create_and_list_clients(api):
    client_id = _client(api)
    assert [c["id"] for c in api.get("/api/v1/clients").json()] == [client_id]
    assert api.get(f"/api/v1/clients/{client_id}").json()["name"] == "Acme Ltd"
    duplicate = api.post("/api/v1/clients", json={"name": "acme ltd"})
    assert duplicate.status_code == 409


def test_aws_connection_returns_setup_details_and_is_idempotent(api):
    client_id = _client(api)
    url = f"/api/v1/clients/{client_id}/connections/aws"
    first = api.post(url, json={"account_id": "111122223333"}).json()
    second = api.post(url, json={"account_id": "111122223333"}).json()

    assert first["connection"]["id"] == second["connection"]["id"]
    assert first["setup"]["external_id"] == first["connection"]["external_id"]
    assert first["setup"]["role_name"] == get_settings().aws_assessment_role_name
    assert len(api.get(f"/api/v1/clients/{client_id}/connections").json()) == 1


def test_azure_connection_and_tenant_conflict(api):
    client_id = _client(api)
    url = f"/api/v1/clients/{client_id}/connections/azure"
    upper = "2222AAAA-2222-2222-2222-222222222222"
    created = api.post(url, json={"tenant_id": upper, "subscription_id": SUB})
    assert created.status_code == 201
    assert created.json()["tenant_id"] == upper.lower()
    other_tenant = "33333333-3333-3333-3333-333333333333"
    conflict = api.post(url, json={"tenant_id": other_tenant, "subscription_id": SUB})
    assert conflict.status_code == 409


@pytest.mark.parametrize(
    "path, body",
    [
        ("connections/aws", {"account_id": "1234"}),
        ("connections/aws", {"account_id": "111122223333", "role_arn": "x"}),  # unknown field
        ("connections/azure", {"tenant_id": "not-a-guid", "subscription_id": SUB}),
    ],
)
def test_invalid_input_is_rejected_without_echoing_it(api, path, body):
    client_id = _client(api)
    response = api.post(f"/api/v1/clients/{client_id}/{path}", json=body)
    assert response.status_code == 422
    assert '"input"' not in response.text
    assert "not-a-guid" not in response.text


# ------------------------------------------------------------------ assessments + scans


def test_assessment_lifecycle_and_scan_request(api):
    client_id = _client(api)
    _, assessment_id = _aws_assessment(api, client_id)
    base = f"/api/v1/clients/{client_id}"

    duplicate = api.post(
        f"{base}/assessments",
        json={"connection_id": api.get(f"{base}/connections").json()[0]["id"], "name": "Q1 review"},
    )
    assert duplicate.status_code == 409

    response = api.post(
        f"{base}/assessments/{assessment_id}/scans", json={"regions": ["EU-West-2"]}
    )
    assert response.status_code == 202, response.text
    job = response.json()
    assert (job["status"], job["stage"], job["regions"]) == ("queued", "waiting", ["eu-west-2"])
    assert response.headers["Location"] == f"{base}/scan-jobs/{job['id']}"
    assert api.get(response.headers["Location"]).json()["id"] == job["id"]

    again = api.post(f"{base}/assessments/{assessment_id}/scans", json={})
    assert again.status_code == 409  # one queued/running scan per assessment
    assert [j["id"] for j in api.get(f"{base}/assessments/{assessment_id}/scan-jobs").json()] == [
        job["id"]
    ]


@pytest.mark.parametrize(
    "body", [{"regions": []}, {"regions": ["eu west"]}, {"regions": ["x"] * 51}, {"all": True}]
)
def test_invalid_scan_requests(api, body):
    client_id = _client(api)
    _, assessment_id = _aws_assessment(api, client_id)
    response = api.post(f"/api/v1/clients/{client_id}/assessments/{assessment_id}/scans", json=body)
    assert response.status_code == 422


def test_assessment_detail_report_and_csv(api, db):
    client_id = _client(api)
    _, assessment_id = _aws_assessment(api, client_id)
    scan = repo.save_scan_result(
        db, uuid.UUID(client_id), uuid.UUID(assessment_id), RuleEngine().run(sample_aws_inventory())
    )
    base = f"/api/v1/clients/{client_id}"

    detail = api.get(f"{base}/assessments/{assessment_id}").json()
    assert detail["status"] == "in_review"
    assert [(s["id"], s["findings"]) for s in detail["scans"]] == [(str(scan.id), 10)]

    report = api.get(f"{base}/scans/{scan.id}/report")
    assert report.status_code == 200
    assert report.json()["source"]["client_name"] == "Acme Ltd"
    assert report.json()["summary"]["total_findings"] == 10

    csv = api.get(f"{base}/scans/{scan.id}/report.csv")
    assert csv.headers["content-type"].startswith("text/csv")
    assert f'filename="acme-ltd_{str(scan.id)[:8]}.csv"' in csv.headers["content-disposition"]
    assert csv.content.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM, as in the CLI export


# ------------------------------------------------------------------ client isolation


def test_another_clients_data_is_not_found(api, db):
    owner = _client(api, "Acme Ltd")
    other = _client(api, "Globex")
    connection_id, assessment_id = _aws_assessment(api, owner)
    job = api.post(f"/api/v1/clients/{owner}/assessments/{assessment_id}/scans", json={}).json()
    scan = repo.save_scan_result(
        db, uuid.UUID(owner), uuid.UUID(assessment_id), RuleEngine().run(sample_aws_inventory())
    )

    base = f"/api/v1/clients/{other}"
    for path in (
        f"assessments/{assessment_id}",
        f"assessments/{assessment_id}/scan-jobs",
        f"scan-jobs/{job['id']}",
        f"scans/{scan.id}/report",
        f"scans/{scan.id}/report.csv",
    ):
        response = api.get(f"{base}/{path}")
        assert response.status_code == 404, path
        assert response.json() == {"detail": "Not found."}

    for path, body in (
        (f"assessments/{assessment_id}/scans", {}),
        ("assessments", {"connection_id": connection_id, "name": "steal"}),
    ):
        assert api.post(f"{base}/{path}", json=body).status_code == 404, path
    assert api.get(f"/api/v1/clients/{uuid.uuid4()}").status_code == 404


# ------------------------------------------------------------------ HTTP protections


def test_changes_must_be_json(api):
    """A cross-site HTML form cannot send JSON, so it cannot create or scan anything."""
    client_id = _client(api)
    _, assessment_id = _aws_assessment(api, client_id)
    for url in (
        "/api/v1/clients",
        f"/api/v1/clients/{client_id}/assessments/{assessment_id}/scans",
    ):
        form = api.post(url, data={"name": "x"})
        plain = api.post(url, content=b'{"name": "x"}', headers={"content-type": "text/plain"})
        assert (form.status_code, plain.status_code) == (415, 415), url


def test_unknown_host_names_are_refused():
    with TestClient(app, base_url="http://attacker.example") as other_host:
        assert other_host.get("/health").status_code == 400


def test_security_headers(api):
    response = api.get("/api/v1/clients")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_data_api_requires_login(http):
    """Without a session cookie every data request is refused (401)."""
    for url in ("/api/v1/clients", f"/api/v1/clients/{uuid.uuid4()}"):
        assert http.get(url).status_code == 401, url
    assert http.post("/api/v1/clients", json={"name": "x"}).status_code == 401
    assert http.get("/health").status_code == 200  # health stays available


def test_onboarding_instructions(api):
    client_id = _client(api)
    aws = api.post(
        f"/api/v1/clients/{client_id}/connections/aws", json={"account_id": "111122223333"}
    ).json()["connection"]
    steps = api.get(f"/api/v1/clients/{client_id}/connections/{aws['id']}/onboarding").json()
    assert steps["external_id"] == aws["external_id"] and steps["provider"] == "aws"

    azure = api.post(
        f"/api/v1/clients/{client_id}/connections/azure",
        json={"tenant_id": TENANT, "subscription_id": SUB},
    ).json()
    steps = api.get(f"/api/v1/clients/{client_id}/connections/{azure['id']}/onboarding").json()
    assert all(f"/subscriptions/{SUB}" in c for c in steps["role_commands"])
    other = _client(api, "Globex")
    assert api.get(f"/api/v1/clients/{other}/connections/{aws['id']}/onboarding").status_code == 404
