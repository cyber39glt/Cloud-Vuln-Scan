"""Authentication, MFA, sessions, roles, client assignment and the audit log (M9)."""

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.auth import mfa, passwords
from app.auth.ratelimit import SlidingWindowLimiter
from app.main import app
from app.storage.models import AuditEvent, Role, User, UserSession
from tests.auth_helpers import PASSWORD, login, make_user, plain_http_settings, totp

pytestmark = pytest.mark.integration


def _login_password(http, email, password=PASSWORD):
    return http.post("/api/v1/auth/login", json={"email": email, "password": password})


def _events(db, action):
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def _fresh(db, user):
    db.expire_all()
    return db.get(User, user.id)


# ------------------------------------------------------------------ first login


def test_new_user_first_login_flow(http, db, admin):
    """Admin creates a consultant -> temporary password -> MFA setup -> password change."""
    login(http, db, *admin)
    created = http.post(
        "/api/v1/admin/users",
        json={"email": "Con@SubtleTech.test", "display_name": "Con", "role": "consultant"},
    )
    assert created.status_code == 201, created.text
    temporary = created.json()["temporary_password"]
    assert created.json()["user"]["email"] == "con@subtletech.test"
    http.post("/api/v1/auth/logout", json={})

    first = _login_password(http, "con@subtletech.test", temporary)
    assert first.json() == {"mfa_enrolled": False, "next_step": "mfa_setup"}
    assert http.get("/api/v1/auth/me").status_code == 401  # password alone is not a login

    setup = http.post("/api/v1/auth/mfa/setup", json={}).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/SubtleTech:con%40subtletech.test?")
    assert http.post("/api/v1/auth/mfa/activate", json={"code": "000000"}).status_code == 401
    activated = http.post("/api/v1/auth/mfa/activate", json={"code": totp(setup["secret"])})
    assert activated.status_code == 200
    assert len(activated.json()["recovery_codes"]) == 10

    me = http.get("/api/v1/auth/me").json()
    assert me["mfa_enabled"] and me["must_change_password"] and me["role"] == "consultant"
    assert http.get("/api/v1/clients").status_code == 403  # must change the password first

    change = "/api/v1/auth/password"
    weak = http.post(change, json={"current_password": temporary, "new_password": "short"})
    assert weak.status_code == 400 and "12 characters" in weak.json()["detail"]
    wrong = http.post(change, json={"current_password": "nope", "new_password": "x" * 20})
    assert wrong.status_code == 400
    ok = http.post(change, json={"current_password": temporary, "new_password": PASSWORD})
    assert ok.status_code == 204
    assert http.get("/api/v1/clients").json() == []  # consultant: nothing assigned yet


def test_mfa_secret_is_encrypted_at_rest(http, db):
    user, _ = make_user(db, "enrol@subtletech.test", mfa_enabled=False)
    _login_password(http, user.email)
    secret = http.post("/api/v1/auth/mfa/setup", json={}).json()["secret"]
    stored = _fresh(db, user).mfa_secret_encrypted
    assert secret not in stored
    assert mfa.decrypt_secret(stored, plain_http_settings().secret_key) == secret
    with pytest.raises(mfa.MfaKeyError):
        mfa.decrypt_secret(stored, "a different key entirely, so decryption must fail")


def test_enrolled_user_cannot_replace_mfa_with_password_alone(http, db):
    user, _ = make_user(db, "victim@subtletech.test")
    assert _login_password(http, user.email).json()["next_step"] == "mfa_verify"
    assert http.post("/api/v1/auth/mfa/setup", json={}).status_code == 409


# ------------------------------------------------------------------ password step


def test_wrong_password_and_unknown_account_look_the_same(http, db):
    make_user(db, "real@subtletech.test")
    wrong = _login_password(http, "real@subtletech.test", "wrong password!")
    unknown = _login_password(http, "nobody@subtletech.test", "wrong password!")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert "set-cookie" not in wrong.headers


def test_lockout_after_repeated_failures(http, db):
    user, secret = make_user(db, "locked@subtletech.test")
    for _ in range(5):
        assert _login_password(http, user.email, "wrong password!").status_code == 401
    assert _fresh(db, user).locked_until is not None
    assert _login_password(http, user.email).status_code == 401  # correct password, still locked
    [event] = _events(db, "auth.lockout")
    assert event.actor_user_id == user.id


def test_login_rate_limit_per_address(http, db):
    for _ in range(20):
        _login_password(http, "nobody@subtletech.test", "x")
    assert _login_password(http, "nobody@subtletech.test", "x").status_code == 429


def test_deactivated_users_cannot_log_in(http, db):
    user, _ = make_user(db, "gone@subtletech.test")
    user.is_active = False
    db.flush()
    assert _login_password(http, user.email).status_code == 401


# ------------------------------------------------------------------ MFA step


def test_totp_code_cannot_be_replayed(http, db):
    user, secret = make_user(db, "replay@subtletech.test")
    code = totp(secret)
    _login_password(http, user.email)
    assert http.post("/api/v1/auth/mfa/verify", json={"code": code}).status_code == 204
    http.post("/api/v1/auth/logout", json={})
    _login_password(http, user.email)
    assert http.post("/api/v1/auth/mfa/verify", json={"code": code}).status_code == 401


def test_too_many_wrong_codes_end_the_pending_session(http, db):
    user, secret = make_user(db, "guess@subtletech.test")
    _login_password(http, user.email)
    for _ in range(5):
        assert http.post("/api/v1/auth/mfa/verify", json={"code": "123456"}).status_code == 401
    response = http.post("/api/v1/auth/mfa/verify", json={"code": totp(secret)})
    assert response.json()["detail"] == "Not logged in."  # start again with the password


def test_recovery_code_works_once(http, db, admin):
    login(http, db, *admin)
    codes = http.post("/api/v1/auth/mfa/recovery-codes", json={"code": "999999"})
    assert codes.status_code == 401  # a current authenticator code is required
    _fresh(db, admin[0]).mfa_last_used_step = None
    db.flush()
    codes = http.post("/api/v1/auth/mfa/recovery-codes", json={"code": totp(admin[1])}).json()
    code = codes["recovery_codes"][0]
    http.post("/api/v1/auth/logout", json={})

    for expected in (204, 401):
        _login_password(http, admin[0].email)
        response = http.post("/api/v1/auth/mfa/verify", json={"recovery_code": code.upper()})
        assert response.status_code == expected
        http.post("/api/v1/auth/logout", json={})
    [used] = _events(db, "mfa.recovery_code_used")
    assert used.details == {"remaining": 9}


# ------------------------------------------------------------------ sessions


def test_session_cookie_is_protected_and_stored_hashed(http, db):
    user, secret = make_user(db, "cookie@subtletech.test")
    response = _login_password(http, user.email)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    token = re.search(r"cvs_session=([^;]+)", cookie).group(1)
    stored = [s.token_hash for s in db.scalars(select(UserSession))]
    assert token not in stored and len(stored[0]) == 64


def test_secure_cookie_by_default(monkeypatch):
    from app.auth import sessions
    from app.core.config import Settings

    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    secure = Settings(_env_file=None)
    assert secure.session_cookie_secure is True
    assert sessions.cookie_name(secure) == "__Host-cvs_session"


def test_mfa_login_issues_a_new_session_token(http, db):
    user, secret = make_user(db, "rotate@subtletech.test")
    _login_password(http, user.email)
    pending = http.cookies.get("cvs_session")
    http.post("/api/v1/auth/mfa/verify", json={"code": totp(secret)})
    assert http.cookies.get("cvs_session") != pending  # no session fixation


def test_logout_ends_the_session(api):
    assert api.post("/api/v1/auth/logout", json={}).status_code == 204
    assert api.get("/api/v1/auth/me").status_code == 401


def test_idle_and_absolute_timeouts(api, db):
    [session] = db.scalars(select(UserSession).where(UserSession.mfa_verified.is_(True)))
    session.last_seen_at = datetime.now(UTC) - timedelta(minutes=31)
    db.flush()
    assert api.get("/api/v1/auth/me").status_code == 401


def test_password_change_ends_other_sessions(http, db):
    from fastapi.testclient import TestClient

    user, secret = make_user(db, "multi@subtletech.test")
    login(http, db, user, secret)
    with TestClient(app, base_url="http://localhost") as other_browser:
        login(other_browser, db, user, secret)
        new = "another long passphrase 42"
        changed = http.post(
            "/api/v1/auth/password", json={"current_password": PASSWORD, "new_password": new}
        )
        assert changed.status_code == 204
        assert other_browser.get("/api/v1/auth/me").status_code == 401
    assert http.get("/api/v1/auth/me").status_code == 200  # this browser got a new session


# ------------------------------------------------------------------ roles and assignment


def _consultant(http, db):
    user, secret = make_user(db, "consultant@subtletech.test", Role.CONSULTANT)
    login(http, db, user, secret)
    return user


def test_consultant_sees_only_assigned_clients(http, db, admin):
    from app.storage import repository as repo

    acme, globex = repo.create_client(db, "Acme Ltd"), repo.create_client(db, "Globex")
    consultant = _consultant(http, db)
    assert http.get(f"/api/v1/clients/{acme.id}").status_code == 404

    from app.auth import audit, service

    service.assign_client(db, consultant, acme.id, audit.CLI)
    db.flush()
    assert [c["name"] for c in http.get("/api/v1/clients").json()] == ["Acme Ltd"]
    assert http.get(f"/api/v1/clients/{acme.id}").status_code == 200
    assert http.get(f"/api/v1/clients/{globex.id}").status_code == 404  # same as nonexistent
    assert http.get(f"/api/v1/clients/{globex.id}/assessments").status_code == 404

    service.unassign_client(db, consultant, acme.id, audit.CLI)
    db.flush()
    assert http.get(f"/api/v1/clients/{acme.id}").status_code == 404


def test_consultants_cannot_administer(http, db):
    _consultant(http, db)
    assert http.get("/api/v1/admin/users").status_code == 403
    assert http.get("/api/v1/admin/audit-events").status_code == 403
    assert http.post("/api/v1/clients", json={"name": "New Co"}).status_code == 403


def test_admin_assigns_clients_and_it_is_audited(api, db):
    client_id = api.post("/api/v1/clients", json={"name": "Acme Ltd"}).json()["id"]
    user = api.post(
        "/api/v1/admin/users",
        json={"email": "c@subtletech.test", "display_name": "C", "role": "consultant"},
    ).json()["user"]
    assigned = api.put(f"/api/v1/admin/users/{user['id']}/clients/{client_id}")
    assert assigned.json()["client_ids"] == [client_id]
    removed = api.delete(f"/api/v1/admin/users/{user['id']}/clients/{client_id}")
    assert removed.json()["client_ids"] == []
    actions = [e["action"] for e in api.get("/api/v1/admin/audit-events").json()]
    assert {"assignment.added", "assignment.removed", "user.created", "client.created"} <= set(
        actions
    )


def test_last_administrator_cannot_be_removed(api, db, admin):
    me = str(admin[0].id)
    for change in ({"role": "consultant"}, {"is_active": False}):
        response = api.patch(f"/api/v1/admin/users/{me}", json=change)
        assert response.status_code == 409, change


def test_deactivation_and_mfa_reset_end_sessions(http, db, admin):
    user, secret = make_user(db, "leaver@subtletech.test", Role.CONSULTANT)
    from fastapi.testclient import TestClient

    with TestClient(app, base_url="http://localhost") as leaver:
        login(leaver, db, user, secret)
        login(http, db, *admin)
        reset = http.post(f"/api/v1/admin/users/{user.id}/reset-mfa", json={})
        assert reset.json()["mfa_enabled"] is False
        assert leaver.get("/api/v1/auth/me").status_code == 401
        assert _login_password(leaver, user.email).json()["next_step"] == "mfa_setup"

        http.patch(f"/api/v1/admin/users/{user.id}", json={"is_active": False})
        assert _login_password(leaver, user.email).status_code == 401
    [reset_event] = _events(db, "mfa.reset")
    assert reset_event.actor_user_id == admin[0].id and reset_event.target_id == str(user.id)


def test_admin_password_reset_returns_a_one_time_password(api, db):
    user, _ = make_user(db, "forgot@subtletech.test", Role.CONSULTANT)
    user.locked_until = datetime.now(UTC) + timedelta(minutes=10)
    db.flush()
    response = api.post(f"/api/v1/admin/users/{user.id}/reset-password", json={})
    temporary = response.json()["temporary_password"]
    user = _fresh(db, user)
    assert user.locked_until is None and user.must_change_password
    assert passwords.verify_password(user.password_hash, temporary)


# ------------------------------------------------------------------ every route is protected


def _api_routes() -> list[tuple[str, str]]:
    """Every API operation, read from the same route list FastAPI uses for its schema
    (included routers are nested, so app.routes alone does not list them)."""
    paths = app.openapi()["paths"]
    return sorted(
        (method.upper(), path)
        for path, operations in paths.items()
        if path.startswith("/api/")
        for method in operations
    )


def test_route_list_is_complete():
    """Guards the test below: it must never silently check zero routes."""
    routes = _api_routes()
    assert len(routes) >= 30
    assert ("GET", "/api/v1/clients/{client_id}/scans/{scan_id}/report") in routes


PUBLIC = {
    ("POST", "/api/v1/auth/login"),
    # First-run setup and invitations (ADR 0024): tested in test_onboarding.py.
    ("GET", "/api/v1/setup"),
    ("POST", "/api/v1/setup"),
    ("POST", "/api/v1/invites/lookup"),
    ("POST", "/api/v1/invites/accept"),
}


@pytest.mark.parametrize("method, path", _api_routes())
def test_every_api_route_requires_a_session(http, method, path):
    """Adding an endpoint without the shared authentication dependency fails here."""
    if (method, path) in PUBLIC:
        pytest.skip("public by design")
    url = re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)
    response = http.request(method, url, json={})
    assert response.status_code == 401, (method, path, response.status_code)


# ------------------------------------------------------------------ audit log


def test_audit_log_is_append_only(api, db):
    db.flush()
    assert db.scalar(select(AuditEvent).limit(1)) is not None
    for statement in ("UPDATE audit_events SET outcome = 'x'", "DELETE FROM audit_events"):
        with pytest.raises(DBAPIError, match="append-only"), db.begin_nested():
            db.execute(text(statement))


def test_audit_entries_contain_no_secrets(http, db):
    user, secret = make_user(db, "audit@subtletech.test")
    _login_password(http, user.email, "my wrong password attempt")
    login(http, db, user, secret)
    dumped = " ".join(str(e.details) for e in db.scalars(select(AuditEvent)))
    assert "my wrong password attempt" not in dumped and PASSWORD not in dumped
    assert secret not in dumped


def test_cross_site_post_is_refused(api):
    response = api.post(
        "/api/v1/clients", json={"name": "x"}, headers={"Origin": "https://evil.example"}
    )
    assert response.status_code == 403


# ------------------------------------------------------------------ units


def test_totp_accepts_clock_drift_but_not_replays_or_garbage():
    secret = mfa.new_secret()
    now = 1_800_000_000.0
    import pyotp

    current = pyotp.TOTP(secret).at(now)
    previous = pyotp.TOTP(secret).at(now - 30)
    step = mfa.verify_code(secret, current, None, now)
    assert step == int(now // 30)
    assert mfa.verify_code(secret, previous, None, now) == step - 1  # 30 s of drift is fine
    assert mfa.verify_code(secret, current, step, now) is None  # already used
    assert mfa.verify_code(secret, pyotp.TOTP(secret).at(now - 120), None, now) is None
    for garbage in ("", "12345", "abcdef", "１２３４５６"):
        assert mfa.verify_code(secret, garbage, None, now) is None


@pytest.mark.parametrize(
    "password, ok",
    [
        ("short", False),
        ("aaaaaaaaaaaaaaaa", False),  # too repetitive
        ("alice-likes-long-passwords", False),  # contains the e-mail name
        ("a long passphrase is good", True),
    ],
)
def test_password_policy(password, ok):
    if ok:
        passwords.check_policy(password, "alice@subtletech.test")
    else:
        with pytest.raises(passwords.WeakPassword):
            passwords.check_policy(password, "alice@subtletech.test")


def test_password_hashes_are_argon2id_and_salted():
    first, second = passwords.hash_password("same"), passwords.hash_password("same")
    assert first.startswith("$argon2id$") and first != second
    assert passwords.verify_password(first, "same") and not passwords.verify_password(first, "x")
    assert not passwords.verify_password(None, "anything")


def test_rate_limiter_window():
    limiter = SlidingWindowLimiter(max_events=2, window_seconds=10)
    assert limiter.allow("ip", now=0) and limiter.allow("ip", now=1)
    assert not limiter.allow("ip", now=2)
    assert limiter.allow("other", now=2)
    assert limiter.allow("ip", now=11)


# ------------------------------------------------------------------ command line


@pytest.fixture
def cli_db(db, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    from app import cli

    factory = sessionmaker(
        bind=db.connection(), join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    monkeypatch.setattr(cli, "get_sessionmaker", lambda: factory)
    return db


def test_cli_bootstraps_the_first_admin(cli_db, capsys, http):
    from app.cli import main

    assert (
        main(["users", "create", "--admin", "--email", "Boss@SubtleTech.test", "--name", "Boss"])
        == 0
    )
    out = capsys.readouterr().out
    temporary = re.search(r"\n    (\S+)\n", out).group(1)
    user = cli_db.scalar(select(User).where(User.email == "boss@subtletech.test"))
    assert user.role == Role.ADMIN and user.must_change_password and not user.mfa_enabled
    assert _login_password(http, user.email, temporary).json()["next_step"] == "mfa_setup"

    assert main(["users", "create", "--email", "boss@subtletech.test", "--name", "Again"]) == 1
    assert "already exists" in capsys.readouterr().out
    [event] = _events(cli_db, "user.created")
    assert event.actor_type == "cli" and event.details["role"] == "admin"


def test_cli_break_glass_resets(cli_db, capsys):
    from app.cli import main

    user, _ = make_user(cli_db, "stuck@subtletech.test")
    assert main(["users", "list"]) == 0
    assert "stuck@subtletech.test  (admin, active, mfa)" in capsys.readouterr().out
    assert main(["users", "reset-mfa", "--email", "stuck@subtletech.test"]) == 0
    assert main(["users", "reset-password", "--email", "stuck@subtletech.test"]) == 0
    user = _fresh(cli_db, user)
    assert not user.mfa_enabled and user.must_change_password
    assert main(["users", "reset-mfa", "--email", "nobody@subtletech.test"]) == 1
    assert {e.action for e in cli_db.scalars(select(AuditEvent))} >= {
        "mfa.reset",
        "user.password_reset",
    }
