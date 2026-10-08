"""Getting people into the platform without public sign-up (ADR 0024).

- First-run setup: while there are NO users, the first administrator can be created
  in the browser. It needs a setup code that only someone with server access can
  get (`users setup-code` on the command line), so a stranger who reaches a fresh
  installation first cannot claim it. The code is derived from APP_SECRET_KEY and is
  never logged. Once any user exists, setup is closed for good.
- Invitations: an administrator creates a one-time link (valid for a limited time)
  and passes it on. The person opens it, chooses a password and sets up MFA. Only a
  hash of the link's token is stored.

As everywhere, failures are audit-logged and returned as results the caller can
commit.
"""

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from app.auth import audit, passwords
from app.auth.audit import Actor
from app.auth.service import AccountError, actor_for, find_user, normalize_email
from app.core.config import Settings
from app.storage.models import Role, User, UserInvite

# Serializes first-run setup: two simultaneous requests cannot both create "the first"
# administrator. An arbitrary constant, used only for this lock.
_SETUP_LOCK_ID = 0x5E7_0001


class OnboardingError(ValueError):
    """The request cannot be done. The message is safe to show."""


def _now() -> datetime:
    return datetime.now(UTC)


# ------------------------------------------------------------------ first-run setup


def setup_code(settings: Settings) -> str:
    """The code that unlocks first-run setup: XXXX-XXXX-XXXX-XXXX (80 bits)."""
    digest = hmac.new(
        settings.secret_key.encode(), b"cloud-vuln-scan first-run setup", hashlib.sha256
    ).digest()
    raw = base64.b32encode(digest).decode()[:16]
    return "-".join(raw[i : i + 4] for i in range(0, 16, 4))


def _normalize_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def setup_needed(db: Session) -> bool:
    return not db.scalar(select(func.count()).select_from(User))


def complete_setup(
    db: Session,
    settings: Settings,
    code: str,
    email: str,
    display_name: str,
    password: str,
    ip: str | None,
) -> User:
    """Create the first administrator. Raises OnboardingError (audit-logged)."""
    if not settings.app_secret_key.get_secret_value():
        # Without its own key the code would derive from the public development key.
        raise OnboardingError(
            "Set APP_SECRET_KEY before first-run setup (scripts/dev.ps1 does this for you)."
        )
    db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _SETUP_LOCK_ID})
    if not setup_needed(db):
        audit.record(db, "setup.completed", audit.ANONYMOUS, outcome="denied", ip_address=ip)
        raise OnboardingError("Setup has already been completed. Log in instead.")
    if not hmac.compare_digest(_normalize_code(code), _normalize_code(setup_code(settings))):
        audit.record(db, "setup.completed", audit.ANONYMOUS, outcome="failure", ip_address=ip)
        raise OnboardingError("The setup code is not valid.")
    email = normalize_email(email)
    _check_password(password, email)
    user = User(
        email=email,
        display_name=display_name.strip(),
        role=Role.ADMIN,
        password_hash=passwords.hash_password(password),
        must_change_password=False,
        password_changed_at=_now(),
    )
    db.add(user)
    db.flush()
    audit.record(
        db, "setup.completed", actor_for(user), target_type="user", target_id=user.id, ip_address=ip
    )
    return user


def _check_password(password: str, email: str) -> None:
    try:
        passwords.check_policy(password, email)
    except passwords.WeakPassword as exc:
        raise OnboardingError(str(exc)) from exc


# ------------------------------------------------------------------ invitations


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _is_pending(invite: UserInvite, now: datetime) -> bool:
    return invite.accepted_at is None and invite.revoked_at is None and invite.expires_at > now


def pending_invites(db: Session) -> list[UserInvite]:
    now = _now()
    return list(
        db.scalars(
            select(UserInvite)
            .where(
                UserInvite.accepted_at.is_(None),
                UserInvite.revoked_at.is_(None),
                UserInvite.expires_at > now,
            )
            .order_by(UserInvite.created_at.desc())
        )
    )


def create_invite(
    db: Session,
    email: str,
    display_name: str,
    role: Role,
    actor: Actor,
    settings: Settings,
    ip: str | None = None,
) -> tuple[UserInvite, str]:
    """Returns the invite and its token (shown once, as part of the link). An earlier
    pending invite for the same address is revoked: only the newest link works."""
    email = normalize_email(email)
    if find_user(db, email) is not None:
        raise AccountError("A user with this e-mail address already exists.")
    now = _now()
    db.execute(
        update(UserInvite)
        .where(
            UserInvite.email == email,
            UserInvite.accepted_at.is_(None),
            UserInvite.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    token = secrets.token_urlsafe(32)
    invite = UserInvite(
        token_hash=_hash(token),
        email=email,
        display_name=display_name.strip(),
        role=role,
        created_by=actor.email or actor.type,
        created_by_user_id=actor.user_id,
        created_at=now,
        expires_at=now + timedelta(hours=settings.invite_valid_hours),
    )
    db.add(invite)
    db.flush()
    audit.record(
        db,
        "invite.created",
        actor,
        target_type="invite",
        target_id=invite.id,
        ip_address=ip,
        email=email,
        role=role.value,
        expires_at=invite.expires_at.isoformat(),
    )
    return invite, token


def revoke_invite(db: Session, invite: UserInvite, actor: Actor, ip: str | None = None) -> None:
    if not _is_pending(invite, _now()):
        raise AccountError("This invitation is no longer pending.")
    invite.revoked_at = _now()
    audit.record(
        db,
        "invite.revoked",
        actor,
        target_type="invite",
        target_id=invite.id,
        ip_address=ip,
        email=invite.email,
    )


def find_pending_invite(db: Session, token: str, *, lock: bool = False) -> UserInvite | None:
    """The pending invite for this token, or None (unknown, used, revoked, expired)."""
    query = select(UserInvite).where(UserInvite.token_hash == _hash(token))
    if lock:
        query = query.with_for_update()
    invite = db.scalar(query)
    return invite if invite is not None and _is_pending(invite, _now()) else None


INVALID_INVITE = "This invitation link is not valid. It may have expired or been used already."


def accept_invite(db: Session, token: str, password: str, ip: str | None) -> User:
    """Create the invited account. Raises OnboardingError (audit-logged)."""
    invite = find_pending_invite(db, token, lock=True)
    if invite is None:
        audit.record(db, "invite.accepted", audit.ANONYMOUS, outcome="failure", ip_address=ip)
        raise OnboardingError(INVALID_INVITE)
    if find_user(db, invite.email) is not None:
        raise OnboardingError("An account with this e-mail address already exists. Log in instead.")
    if invite.created_by_user_id is not None:
        creator = db.get(User, invite.created_by_user_id)
        if creator is None or not creator.is_active or creator.role != Role.ADMIN:
            # Defence in depth: removing an admin also revokes their invitations.
            audit.record(db, "invite.accepted", audit.ANONYMOUS, outcome="failure", ip_address=ip)
            raise OnboardingError(INVALID_INVITE)
    _check_password(password, invite.email)
    now = _now()
    user = User(
        email=invite.email,
        display_name=invite.display_name,
        role=invite.role,
        password_hash=passwords.hash_password(password),
        must_change_password=False,
        password_changed_at=now,
    )
    db.add(user)
    db.flush()
    invite.accepted_at = now
    invite.accepted_user_id = user.id
    audit.record(
        db,
        "invite.accepted",
        actor_for(user),
        target_type="invite",
        target_id=invite.id,
        ip_address=ip,
        role=invite.role.value,
    )
    return user
