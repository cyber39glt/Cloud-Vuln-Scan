"""Server-side login sessions stored in PostgreSQL.

The browser holds only a random 256-bit token in an HttpOnly cookie; the database
stores its SHA-256 hash. A session is either:
- pending: password checked, MFA not yet done. Short-lived; usable only to finish MFA.
- verified: password and MFA done. Expires after an idle period or an absolute limit,
  whichever comes first, and is deleted on logout or password/MFA changes.
A new token is issued whenever the session's privilege changes (no session fixation).
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.storage.models import User, UserSession

# Only refresh "last seen" this often, to avoid a database write on every request.
_TOUCH_INTERVAL = timedelta(seconds=60)


def cookie_name(settings: Settings) -> str:
    # The __Host- prefix makes browsers insist on Secure, Path=/ and no Domain.
    return "__Host-cvs_session" if settings.session_cookie_secure else "cvs_session"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def create(db: Session, user: User, *, mfa_verified: bool, settings: Settings) -> str:
    """Start a session and return its token (to be put in the cookie)."""
    now = _now()
    lifetime = (
        timedelta(hours=settings.session_absolute_hours)
        if mfa_verified
        else timedelta(minutes=settings.session_pending_mfa_minutes)
    )
    # Housekeeping: drop this user's expired sessions.
    db.execute(
        delete(UserSession).where(UserSession.user_id == user.id, UserSession.expires_at < now)
    )
    token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_hash=_hash(token),
            user_id=user.id,
            mfa_verified=mfa_verified,
            created_at=now,
            last_seen_at=now,
            expires_at=now + lifetime,
        )
    )
    db.flush()
    return token


def resolve(db: Session, token: str | None, settings: Settings) -> tuple[UserSession, User] | None:
    """The live session and user for a cookie token, or None."""
    if not token or len(token) > 128:
        return None
    row = db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == _hash(token))
    ).first()
    if row is None:
        return None
    session, user = row
    now = _now()
    idle_limit = timedelta(minutes=settings.session_idle_minutes)
    expired = session.expires_at <= now or (
        session.mfa_verified and session.last_seen_at <= now - idle_limit
    )
    if expired or not user.is_active:
        db.delete(session)
        return None
    if now - session.last_seen_at >= _TOUCH_INTERVAL:
        session.last_seen_at = now
    return session, user


def rotate(
    db: Session, session: UserSession, user: User, *, mfa_verified: bool, settings: Settings
) -> str:
    """Replace a session with a new one (new token), e.g. after MFA succeeds."""
    db.delete(session)
    db.flush()
    return create(db, user, mfa_verified=mfa_verified, settings=settings)


def revoke(db: Session, session: UserSession) -> None:
    db.delete(session)


def revoke_all(db: Session, user_id: uuid.UUID) -> int:
    """End every session of a user (password reset, MFA reset, deactivation)."""
    return db.execute(delete(UserSession).where(UserSession.user_id == user_id)).rowcount
