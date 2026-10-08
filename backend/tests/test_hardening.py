"""Regression tests for the M13 security review findings (ADR 0025)."""

import csv
import io

import pytest
from sqlalchemy import delete, select, text

from app.api.security import HSTS
from app.auth import onboarding, service
from app.domain.enums import Provider
from app.main import create_app
from app.reporting.exports import to_csv
from app.reporting.report import report_for_scan
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory
from app.storage import repository as repo
from app.storage.models import (
    AssessmentFinalization,
    AssessmentStatus,
    AuditEvent,
    Role,
    User,
    UserInvite,
)
from app.worker import _describe_failure
from tests.auth_helpers import PASSWORD, login, make_user, plain_http_settings

pytestmark = pytest.mark.integration


def _fresh(db, user):
    db.expire_all()
    return db.get(User, user.id)


# ------------------------------------------------------------------ MFA brute force


def test_wrong_codes_count_towards_account_lockout_across_logins(http, db):
    """A stolen password must not buy unlimited authenticator-code guesses: wrong
    codes count on the account, and a correct password does not reset the count."""
    user, _ = make_user(db, "target@subtletech.test")
    for attempts in (3, 2):  # two fresh logins, 5 wrong codes in total
        assert (
            http.post(
                "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}
            ).status_code
            == 200
        )
        for _ in range(attempts):
            assert http.post("/api/v1/auth/mfa/verify", json={"code": "000000"}).status_code == 401
    assert _fresh(db, user).locked_until is not None
    # Locked: even the right password is refused now.
    response = http.post("/api/v1/auth/login", json={"email": user.email, "password": PASSWORD})
    assert response.status_code == 401
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "auth.lockout")) is not None


def test_complete_login_resets_the_failure_count(http, db):
    user, secret = make_user(db, "ok@subtletech.test")
    http.post("/api/v1/auth/login", json={"email": user.email, "password": PASSWORD})
    http.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
    assert _fresh(db, user).failed_login_count == 1
    login(http, db, user, secret)
    assert _fresh(db, user).failed_login_count == 0


# ------------------------------------------------------------------ first-run setup


def test_setup_refuses_without_a_configured_secret_key(db):
    from app.core.config import Settings

    keyless = Settings(_env_file=None, session_cookie_secure=False)
    with pytest.raises(onboarding.OnboardingError, match="APP_SECRET_KEY"):
        onboarding.complete_setup(
            db, keyless, onboarding.setup_code(keyless), "a@b.test", "A", "a long passphrase!", None
        )


def test_production_image_defaults_to_production_mode():
    from pathlib import Path

    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
    prod_stage = dockerfile.split("AS prod", 1)[1]
    assert "ENV APP_ENV=production" in prod_stage


# ------------------------------------------------------------------ invitations


def test_removing_an_admin_revokes_their_pending_invites(api, db, admin):
    other, _ = make_user(db, "other-admin@subtletech.test")
    invite, token = onboarding.create_invite(
        db,
        "friend@example.test",
        "Friend",
        Role.ADMIN,
        service.actor_for(other),
        plain_http_settings(),
    )
    response = api.patch(f"/api/v1/admin/users/{other.id}", json={"is_active": False})
    assert response.status_code == 200, response.text
    db.expire_all()
    assert db.get(UserInvite, invite.id).revoked_at is not None
    assert onboarding.find_pending_invite(db, token) is None


def test_invite_from_a_former_admin_cannot_be_accepted(db):
    creator, _ = make_user(db, "creator@subtletech.test")
    _, token = onboarding.create_invite(
        db,
        "late@example.test",
        "Late",
        Role.ADMIN,
        service.actor_for(creator),
        plain_http_settings(),
    )
    creator.role = Role.CONSULTANT  # changed without going through update_user
    db.flush()
    with pytest.raises(onboarding.OnboardingError):
        onboarding.accept_invite(db, token, "a long and unusual passphrase", None)


# ------------------------------------------------------------------ finalization integrity


@pytest.fixture
def scanned(db):
    client = repo.create_client(db, "Acme Ltd")
    connection = repo.get_or_create_aws_connection(db, client.id, "111122223333", "SubtleTech")
    assessment = repo.create_assessment(db, client.id, connection.id, "Q1")
    result = RuleEngine().run(sample_aws_inventory())
    scan = repo.save_scan_result(db, client.id, assessment.id, result)
    return client, assessment, scan, result


def test_scan_result_is_not_saved_into_a_finalized_assessment(db, scanned):
    client, assessment, _, result = scanned
    assessment.status = AssessmentStatus.FINALIZED
    db.flush()
    with pytest.raises(repo.AssessmentLocked) as caught:
        repo.save_scan_result(db, client.id, assessment.id, result)
    code, message = _describe_failure(Provider.AWS, caught.value)
    assert code == "AssessmentFinalized" and "not saved" in message


def test_finalized_assessment_without_snapshot_is_an_integrity_error(db, scanned):
    client, assessment, scan, _ = scanned
    assessment.status = AssessmentStatus.FINALIZED
    db.flush()
    db.execute(delete(AssessmentFinalization))
    with pytest.raises(repo.IntegrityViolation):
        report_for_scan(db, client.id, scan.id, "SubtleTech")


def test_status_checks_lock_the_assessment_row(db, scanned):
    """The finalize / review / scan paths read the assessment FOR UPDATE."""
    client, assessment, _, _ = scanned
    repo.get_assessment(db, client.id, assessment.id, for_update=True)
    locks = db.execute(
        text(
            "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
            "WHERE c.relname = 'assessments' AND l.mode = 'RowShareLock' "
            "AND l.pid = pg_backend_pid()"
        )
    ).scalar()
    assert locks >= 1


# ------------------------------------------------------------------ CSV and headers


def test_csv_quotes_every_field_so_semicolon_locales_cannot_split_cells(db, scanned):
    client, assessment, scan, _ = scanned
    report = report_for_scan(db, client.id, scan.id, "SubtleTech")
    hostile = report.findings[0].model_copy(update={"resource_name": "web;=1+1"})
    report = report.model_copy(update={"findings": (hostile, *report.findings[1:])})
    data = to_csv(report).decode("utf-8-sig")
    first_row = data.splitlines()[1]
    assert first_row.startswith('"') and '"web;=1+1"' in first_row
    rows = list(csv.reader(io.StringIO(data)))
    assert rows[1][rows[0].index("resource_name")] == "web;=1+1"


def test_isolation_headers_everywhere_and_hsts_only_in_production(http):
    response = http.get("/health")
    assert response.headers["Permissions-Policy"].startswith("camera=()")
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_in_production(monkeypatch):
    from fastapi.testclient import TestClient

    from app.core import config

    production = config.Settings(
        _env_file=None,
        app_env="production",
        postgres_password="a-real-database-password-1234",
        app_secret_key="x" * 48,
    )
    monkeypatch.setattr(config, "get_settings", lambda: production)
    import app.main as main

    monkeypatch.setattr(main, "get_settings", lambda: production)
    with TestClient(create_app(), base_url="http://localhost") as client:
        assert client.get("/health").headers["Strict-Transport-Security"] == HSTS


def test_unassigning_an_unknown_client_is_not_found(api, db):
    import uuid

    user, _ = make_user(db, "con@subtletech.test", Role.CONSULTANT)
    response = api.delete(f"/api/v1/admin/users/{user.id}/clients/{uuid.uuid4()}")
    assert response.status_code == 404
