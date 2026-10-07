"""Backend support for the dashboard: the overview endpoint and serving the built app."""

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.security import DASHBOARD_CSP, SecurityMiddleware
from app.auth import audit, service
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory
from app.storage import jobs
from app.storage import repository as repo
from app.storage.models import Role
from app.web import mount_dashboard
from tests.auth_helpers import login, make_user

pytestmark = pytest.mark.integration


def _assessment_with_scan(db, name: str):
    client = repo.create_client(db, name)
    connection = repo.get_or_create_aws_connection(db, client.id, "111122223333", "SubtleTech")
    assessment = repo.create_assessment(db, client.id, connection.id, "Q1")
    scan = repo.save_scan_result(
        db, client.id, assessment.id, RuleEngine().run(sample_aws_inventory())
    )
    return client, assessment, scan


def test_overview_shows_latest_scan_counts_and_active_jobs(api, db):
    client, assessment, scan = _assessment_with_scan(db, "Acme Ltd")
    job = jobs.enqueue_scan(db, client.id, assessment.id)

    data = api.get("/api/v1/overview").json()
    [item] = data["items"]
    assert data["clients"] == 1
    assert item["client_name"] == "Acme Ltd" and item["provider"] == "aws"
    assert item["latest_scan"]["id"] == str(scan.id)
    assert item["latest_scan"]["findings"] == 10
    assert item["latest_scan"]["by_severity"]["high"] == 6
    assert item["active_job"] == {"id": str(job.id), "status": "queued", "stage": "waiting"}


def test_overview_is_client_scoped(http, db):
    acme, _, _ = _assessment_with_scan(db, "Acme Ltd")
    _assessment_with_scan(db, "Globex")
    consultant, secret = make_user(db, "c@subtletech.test", Role.CONSULTANT)
    service.assign_client(db, consultant, acme.id, audit.CLI)
    login(http, db, consultant, secret)

    names = {i["client_name"] for i in http.get("/api/v1/overview").json()["items"]}
    assert names == {"Acme Ltd"}


def test_me_includes_the_consultancy_name(api):
    assert api.get("/api/v1/auth/me").json()["consultancy"] == "SubtleTech"


# ------------------------------------------------------------------ serving the built app


@pytest.fixture
def dashboard(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (dist / "assets" / "app-1234.js").write_text("console.log(1)", encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside the build", encoding="utf-8")

    application = FastAPI()
    application.add_middleware(SecurityMiddleware, allowed_hosts=["localhost"])

    @application.get("/api/v1/thing")
    def thing() -> dict:
        return {"ok": True}

    assert mount_dashboard(application, dist)
    with TestClient(application, base_url="http://localhost") as client:
        yield client


def test_dashboard_routes_serve_index_and_files(dashboard):
    page = dashboard.get(f"/clients/{uuid.uuid4()}")
    assert page.status_code == 200 and "root" in page.text
    assert page.headers["content-security-policy"] == DASHBOARD_CSP
    assert "unsafe-inline" not in DASHBOARD_CSP

    asset = dashboard.get("/assets/app-1234.js")
    assert asset.text == "console.log(1)"
    assert "immutable" in asset.headers["cache-control"]
    assert dashboard.get("/favicon.svg").text == "<svg/>"


def test_api_keeps_its_strict_policy_and_404s(dashboard):
    api = dashboard.get("/api/v1/thing")
    assert api.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert dashboard.get("/api/v1/unknown").status_code == 404  # not the dashboard page


@pytest.mark.parametrize(
    "path", ["/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt"]
)
def test_no_files_outside_the_build_are_served(dashboard, path):
    response = dashboard.get(path)
    assert "outside the build" not in response.text


def test_no_dashboard_when_not_built(tmp_path):
    assert mount_dashboard(FastAPI(), tmp_path / "missing") is False
