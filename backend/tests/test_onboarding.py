"""First-run setup and invitation links (ADR 0024)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.auth import onboarding
from app.storage.models import AuditEvent, Role, User, UserInvite
from tests.auth_helpers import login, make_user, plain_http_settings, totp

pytestmark = pytest.mark.integration

NEW_PASSWORD = "a long and unusual passphrase"  # gitleaks:allow  (test-only)


def _events(db, action, outcome="success"):
    return list(
        db.scalars(
            select(AuditEvent).where(AuditEvent.action == action, AuditEvent.outcome == outcome)
        )
    )


def _finish_mfa(http):
    """Continue a pending session into a full login, as the dashboard does."""
    setup = http.post("/api/v1/auth/mfa/setup", json={}).json()
    activated = http.post("/api/v1/auth/mfa/activate", json={"code": totp(setup["secret"])})
    assert activated.status_code == 200, activated.text
    return http.get("/api/v1/auth/me").json()


# ------------------------------------------------------------------ first-run setup


def _setup_body(**overrides):
    body = {
        "setup_code": onboarding.setup_code(plain_http_settings()),
        "email": "Owner@SubtleTech.test",
        "display_name": "Owner",
        "password": NEW_PASSWORD,
    }
    return body | overrides


def test_setup_code_format_and_tolerant_matching():
    code = onboarding.setup_code(plain_http_settings())
    assert len(code) == 19 and code.count("-") == 3
    assert onboarding._normalize_code(code.lower().replace("-", " ")) == code.replace("-", "")


def test_first_run_setup_creates_admin_then_requires_mfa(http, db):
    assert http.get("/api/v1/setup").json() == {"needed": True}

    response = http.post("/api/v1/setup", json=_setup_body())
    assert response.status_code == 200, response.text
    assert response.json() == {"mfa_enrolled": False, "next_step": "mfa_setup"}
    # A password alone is not a login: MFA must be set up first.
    assert http.get("/api/v1/auth/me").status_code == 401

    me = _finish_mfa(http)
    assert me["email"] == "owner@subtletech.test"
    assert me["role"] == "admin" and me["mfa_enabled"] and not me["must_change_password"]
    assert http.get("/api/v1/setup").json() == {"needed": False}
    assert len(_events(db, "setup.completed")) == 1


def test_setup_closes_once_any_user_exists(http, db, admin):
    assert http.get("/api/v1/setup").json() == {"needed": False}
    response = http.post("/api/v1/setup", json=_setup_body())
    assert response.status_code == 400
    assert "already been completed" in response.json()["detail"]
    assert db.scalar(select(User).where(User.email == "owner@subtletech.test")) is None
    assert len(_events(db, "setup.completed", "denied")) == 1


def test_setup_refuses_wrong_code_and_weak_password(http, db):
    wrong = http.post("/api/v1/setup", json=_setup_body(setup_code="AAAA-BBBB-CCCC-DDDD"))
    assert wrong.status_code == 400 and "setup code" in wrong.json()["detail"]
    assert len(_events(db, "setup.completed", "failure")) == 1

    weak = http.post("/api/v1/setup", json=_setup_body(password="short"))
    assert weak.status_code == 400 and "12 characters" in weak.json()["detail"]
    assert http.get("/api/v1/setup").json() == {"needed": True}


def test_setup_code_depends_on_the_secret_key():
    from app.core.config import Settings

    a = onboarding.setup_code(Settings(_env_file=None, app_secret_key="a" * 40))
    b = onboarding.setup_code(Settings(_env_file=None, app_secret_key="b" * 40))
    assert a != b


# ------------------------------------------------------------------ invitations


def _invite(api, email="New.Person@SubtleTech.test", role="consultant"):
    response = api.post(
        "/api/v1/admin/invites", json={"email": email, "display_name": "New Person", "role": role}
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_invite_flow_creates_account_with_mfa(api, http, db):
    created = _invite(api)
    token = created["token"]
    assert created["invite"]["email"] == "new.person@subtletech.test"
    # Only the hash is stored.
    stored = db.scalar(select(UserInvite))
    assert stored.token_hash != token and token not in str(stored.__dict__)
    assert [i["email"] for i in api.get("/api/v1/admin/invites").json()] == [
        "new.person@subtletech.test"
    ]
    api.post("/api/v1/auth/logout", json={})

    info = http.post("/api/v1/invites/lookup", json={"token": token})
    assert info.status_code == 200
    assert info.json()["email"] == "new.person@subtletech.test"
    assert info.json()["role"] == "consultant"

    accepted = http.post("/api/v1/invites/accept", json={"token": token, "password": NEW_PASSWORD})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["next_step"] == "mfa_setup"
    me = _finish_mfa(http)
    assert me["role"] == "consultant" and me["display_name"] == "New Person"
    assert len(_events(db, "invite.accepted")) == 1

    # The link works once.
    http.post("/api/v1/auth/logout", json={})
    again = http.post("/api/v1/invites/accept", json={"token": token, "password": NEW_PASSWORD})
    assert again.status_code == 400
    assert http.post("/api/v1/invites/lookup", json={"token": token}).status_code == 404


def test_invited_consultant_sees_no_clients_until_assigned(api, http, db):
    api.post("/api/v1/clients", json={"name": "Acme"})
    token = _invite(api)["token"]
    api.post("/api/v1/auth/logout", json={})
    http.post("/api/v1/invites/accept", json={"token": token, "password": NEW_PASSWORD})
    _finish_mfa(http)
    assert http.get("/api/v1/clients").json() == []
    assert http.get("/api/v1/admin/users").status_code == 403


def test_expired_and_revoked_invites_do_not_work(api, http, db):
    expired = _invite(api, "late@subtletech.test")
    invite = db.get(UserInvite, expired["invite"]["id"])
    invite.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.flush()
    lookup = http.post("/api/v1/invites/lookup", json={"token": expired["token"]})
    assert lookup.status_code == 404

    revoked = _invite(api, "gone@subtletech.test")
    assert api.delete(f"/api/v1/admin/invites/{revoked['invite']['id']}").status_code == 204
    assert api.delete(f"/api/v1/admin/invites/{revoked['invite']['id']}").status_code == 409
    accept = http.post(
        "/api/v1/invites/accept", json={"token": revoked["token"], "password": NEW_PASSWORD}
    )
    assert accept.status_code == 400
    assert api.get("/api/v1/admin/invites").json() == []
    assert len(_events(db, "invite.revoked")) == 1


def test_new_invite_replaces_the_previous_one(api, db):
    first = _invite(api, "twice@subtletech.test")
    second = _invite(api, "twice@subtletech.test")
    assert onboarding.find_pending_invite(db, first["token"]) is None
    assert onboarding.find_pending_invite(db, second["token"]) is not None


def test_invite_refused_for_existing_user_and_weak_password(api, http, db, admin):
    existing = api.post(
        "/api/v1/admin/invites",
        json={"email": admin[0].email, "display_name": "Dup", "role": "admin"},
    )
    assert existing.status_code == 409

    token = _invite(api)["token"]
    weak = http.post("/api/v1/invites/accept", json={"token": token, "password": "tiny"})
    assert weak.status_code == 400
    assert onboarding.find_pending_invite(db, token) is not None  # still usable


def test_only_admins_manage_invites(http, db):
    consultant, secret = make_user(db, "con@subtletech.test", Role.CONSULTANT)
    login(http, db, consultant, secret)
    assert http.get("/api/v1/admin/invites").status_code == 403
    body = {"email": "x@subtletech.test", "display_name": "X", "role": "admin"}
    assert http.post("/api/v1/admin/invites", json=body).status_code == 403


def test_public_onboarding_endpoints_are_rate_limited(http, db):
    from app.auth.ratelimit import login_limiter

    for _ in range(login_limiter.max_events):
        http.post("/api/v1/invites/lookup", json={"token": "x" * 40})
    limited = http.post("/api/v1/invites/lookup", json={"token": "x" * 40})
    assert limited.status_code == 429


def test_invite_token_never_in_audit_log(api, db):
    token = _invite(api)["token"]
    for event in db.scalars(select(AuditEvent)):
        assert token not in str(event.details)
