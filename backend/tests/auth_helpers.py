"""Test helpers: users with known passwords and authenticator secrets, and logging
in through the real API (password step + TOTP step)."""

import pyotp
from sqlalchemy.orm import Session

from app.auth import mfa, passwords
from app.core.config import Settings
from app.storage.models import Role, User

PASSWORD = "correct horse battery staple"  # gitleaks:allow  (test-only)
_PASSWORD_HASH = passwords.hash_password(PASSWORD)  # hashed once: Argon2id is slow on purpose


def plain_http_settings() -> Settings:
    # Plain-HTTP test client: the Secure cookie flag would stop it sending the cookie.
    return Settings(
        _env_file=None,
        session_cookie_secure=False,
        app_secret_key="test-only-secret-key-0123456789-abcdefghijklmnop",  # gitleaks:allow
    )


def make_user(
    db: Session,
    email: str,
    role: Role = Role.ADMIN,
    *,
    mfa_enabled: bool = True,
    must_change_password: bool = False,
    settings: Settings | None = None,
) -> tuple[User, str | None]:
    """A user (and their TOTP secret, if MFA is enabled)."""
    settings = settings or plain_http_settings()
    secret = mfa.new_secret() if mfa_enabled else None
    user = User(
        email=email,
        display_name=email.split("@")[0],
        role=role,
        password_hash=_PASSWORD_HASH,
        must_change_password=must_change_password,
        mfa_enabled=mfa_enabled,
        mfa_secret_encrypted=mfa.encrypt_secret(secret, settings.secret_key) if secret else None,
    )
    db.add(user)
    db.flush()
    return user, secret


def totp(secret: str) -> str:
    return pyotp.TOTP(secret).now()


def login(client, db: Session, user: User, secret: str, password: str = PASSWORD) -> None:
    """Log in through the API. Clears the replay marker first, because several logins
    in one test happen within the same 30-second window."""
    response = client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    assert response.status_code == 200, response.text
    db.expire_all()
    user = db.get(User, user.id)
    user.mfa_last_used_step = None
    db.flush()
    response = client.post("/api/v1/auth/mfa/verify", json={"code": totp(secret)})
    assert response.status_code == 204, response.text
