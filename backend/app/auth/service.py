"""Account operations: login, MFA, password changes and user administration.

Every function records what happened in the audit log. Failures return a result
instead of raising, so the caller can COMMIT the failure (counter, lockout, audit
entry) and still answer the request with an error.
"""

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.orm import Session

from app.auth import audit, mfa, passwords
from app.auth import sessions as auth_sessions
from app.auth.audit import Actor
from app.core.config import Settings
from app.storage.models import (
    ClientAssignment,
    RecoveryCode,
    Role,
    User,
    UserInvite,
    UserSession,
)

MAX_MFA_FAILURES_PER_SESSION = 5
# Serializes changes that could remove the last administrator (an arbitrary constant).
_ADMIN_CHANGE_LOCK_ID = 0x5E7_0002
GENERIC_LOGIN_ERROR = "Invalid e-mail or password, or the account is temporarily locked."


class AccountError(ValueError):
    """An administrative request that cannot be done. The message is safe to show."""


def _now() -> datetime:
    return datetime.now(UTC)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def actor_for(user: User) -> Actor:
    return Actor("user", user.id, user.email)


def find_user(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == normalize_email(email)))


def temporary_password() -> str:
    """A random password for new accounts and resets; must be changed at first login."""
    return secrets.token_urlsafe(15)  # 20 characters, about 120 bits


# ------------------------------------------------------------------ login (password step)


def authenticate(
    db: Session, email: str, password: str, settings: Settings, ip: str | None
) -> User | None:
    """Check e-mail + password. Returns the user, or None (with the failure recorded).
    The same work is done whether or not the account exists."""
    user = find_user(db, email)
    now = _now()
    usable = user is not None and user.is_active and user.auth_provider == "local"
    locked = user is not None and user.locked_until is not None and user.locked_until > now
    valid = passwords.verify_password(user.password_hash if usable else None, password)

    if usable and valid and not locked:
        # The failure counter is NOT reset here: only a complete login (password AND
        # second factor, see finish_login) resets it. Otherwise a stolen password
        # would buy unlimited authenticator-code guesses, five per fresh login.
        user.locked_until = None
        if user.password_hash and passwords.needs_rehash(user.password_hash):
            user.password_hash = passwords.hash_password(password)
        audit.record(db, "auth.password", actor_for(user), ip_address=ip)
        return user

    reason = (
        "unknown_account"
        if user is None
        else "locked"
        if locked
        else "inactive_or_external"
        if not usable
        else "wrong_password"
    )
    if user is not None and reason == "wrong_password":
        user.failed_login_count += 1
        if user.failed_login_count >= settings.max_failed_logins:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            user.failed_login_count = 0
            audit.record(
                db,
                "auth.lockout",
                actor_for(user),
                outcome="failure",
                ip_address=ip,
                minutes=settings.lockout_minutes,
            )
    # The attempted e-mail is recorded only for real accounts: for unknown ones it may
    # be a mistyped password.
    actor = actor_for(user) if user is not None else audit.ANONYMOUS
    audit.record(db, "auth.password", actor, outcome="failure", ip_address=ip, reason=reason)
    return None


# ------------------------------------------------------------------ MFA


@dataclass(frozen=True)
class MfaSetup:
    secret: str
    otpauth_uri: str


def start_enrollment(db: Session, user: User, settings: Settings, ip: str | None) -> MfaSetup:
    """Create a new TOTP secret for a user who has no MFA yet. A user WITH MFA cannot
    replace it here (that would let a stolen password take over the account); an
    admin must reset it first."""
    if user.mfa_enabled:
        raise AccountError("MFA is already set up for this account.")
    secret = mfa.new_secret()
    user.mfa_secret_encrypted = mfa.encrypt_secret(secret, settings.secret_key)
    user.mfa_last_used_step = None
    audit.record(db, "mfa.enrollment_started", actor_for(user), ip_address=ip)
    return MfaSetup(
        secret=secret,
        otpauth_uri=mfa.provisioning_uri(secret, user.email, settings.consultancy_name),
    )


def _lock_user_row(db: Session, user: User) -> None:
    """Serialize second-factor checks per user (SELECT ... FOR UPDATE) and reload the
    user, so two simultaneous requests cannot both use the same one-time code."""
    db.refresh(user, with_for_update=True)


def _is_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > _now()


def _mfa_failure(
    db: Session,
    session: UserSession,
    user: User,
    settings: Settings,
    ip: str | None,
    action: str,
    method: str,
) -> None:
    """Count a wrong code against the session AND the account. Too many on the
    session ends it; too many on the account (wrong passwords and wrong codes
    together, since the last complete login) locks the account."""
    session.mfa_failures += 1
    user.failed_login_count += 1
    audit.record(
        db,
        action,
        actor_for(user),
        outcome="failure",
        ip_address=ip,
        method=method,
        failures=session.mfa_failures,
    )
    if user.failed_login_count >= settings.max_failed_logins:
        user.locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
        user.failed_login_count = 0
        audit.record(
            db,
            "auth.lockout",
            actor_for(user),
            outcome="failure",
            ip_address=ip,
            minutes=settings.lockout_minutes,
        )
        auth_sessions.revoke(db, session)
    elif session.mfa_failures >= MAX_MFA_FAILURES_PER_SESSION:
        auth_sessions.revoke(db, session)


def complete_enrollment(
    db: Session,
    session: UserSession,
    user: User,
    code: str,
    settings: Settings,
    ip: str | None,
) -> list[str] | None:
    """Confirm the authenticator works; returns the new recovery codes (shown once)."""
    _lock_user_row(db, user)
    if user.mfa_enabled or not user.mfa_secret_encrypted:
        raise AccountError("Start MFA setup first.")
    if _is_locked(user):
        auth_sessions.revoke(db, session)
        return None
    secret = mfa.decrypt_secret(user.mfa_secret_encrypted, settings.secret_key)
    step = mfa.verify_code(secret, code, user.mfa_last_used_step)
    if step is None:
        _mfa_failure(db, session, user, settings, ip, "mfa.enrollment", "totp")
        return None
    user.mfa_enabled = True
    user.mfa_last_used_step = step
    codes = _replace_recovery_codes(db, user)
    audit.record(db, "mfa.enrolled", actor_for(user), ip_address=ip)
    return codes


def _replace_recovery_codes(db: Session, user: User) -> list[str]:
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = mfa.new_recovery_codes()
    db.add_all(RecoveryCode(user_id=user.id, code_hash=mfa.hash_recovery_code(c)) for c in codes)
    return codes


def verify_second_factor(
    db: Session,
    session: UserSession,
    user: User,
    settings: Settings,
    ip: str | None,
    *,
    code: str | None = None,
    recovery_code: str | None = None,
) -> bool:
    """Check a TOTP code or a recovery code for a pending session. After too many
    failures the session is ended and the password must be entered again."""
    _lock_user_row(db, user)
    if not user.mfa_enabled or not user.mfa_secret_encrypted:
        return False
    if _is_locked(user):
        audit.record(
            db, "mfa.verify", actor_for(user), outcome="failure", ip_address=ip, reason="locked"
        )
        auth_sessions.revoke(db, session)
        return False
    if code:
        secret = mfa.decrypt_secret(user.mfa_secret_encrypted, settings.secret_key)
        step = mfa.verify_code(secret, code, user.mfa_last_used_step)
        if step is not None:
            user.mfa_last_used_step = step
            audit.record(db, "mfa.verify", actor_for(user), ip_address=ip, method="totp")
            return True
    elif recovery_code:
        stored = db.scalar(
            select(RecoveryCode).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.code_hash == mfa.hash_recovery_code(recovery_code),
                RecoveryCode.used_at.is_(None),
            )
        )
        if stored is not None:
            stored.used_at = _now()
            db.flush()
            remaining = db.scalar(
                select(func.count()).where(
                    RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
                )
            )
            audit.record(
                db, "mfa.recovery_code_used", actor_for(user), ip_address=ip, remaining=remaining
            )
            return True

    _mfa_failure(db, session, user, settings, ip, "mfa.verify", "totp" if code else "recovery_code")
    return False


def finish_login(db: Session, user: User) -> None:
    """A complete login (password and second factor): reset the failure counter."""
    user.last_login_at = _now()
    user.failed_login_count = 0


def regenerate_recovery_codes(db: Session, user: User, ip: str | None) -> list[str]:
    codes = _replace_recovery_codes(db, user)
    audit.record(db, "mfa.recovery_codes_regenerated", actor_for(user), ip_address=ip)
    return codes


# ------------------------------------------------------------------ passwords


def change_password(db: Session, user: User, current: str, new: str, ip: str | None) -> str | None:
    """Returns None on success, or a message explaining the refusal."""
    if not passwords.verify_password(user.password_hash, current):
        audit.record(db, "auth.password_change", actor_for(user), outcome="failure", ip_address=ip)
        return "The current password is wrong."
    if new == current:
        return "Choose a password different from the current one."
    try:
        passwords.check_policy(new, user.email)
    except passwords.WeakPassword as exc:
        return str(exc)
    user.password_hash = passwords.hash_password(new)
    user.must_change_password = False
    user.password_changed_at = _now()
    audit.record(db, "auth.password_change", actor_for(user), ip_address=ip)
    return None


# ------------------------------------------------------------------ administration


def create_user(
    db: Session, email: str, display_name: str, role: Role, actor: Actor, ip: str | None = None
) -> tuple[User, str]:
    """Create a local account with a temporary password (returned once). The user
    must change it and set up MFA at first login."""
    email = normalize_email(email)
    if find_user(db, email) is not None:
        raise AccountError("A user with this e-mail address already exists.")
    password = temporary_password()
    user = User(
        email=email,
        display_name=display_name.strip(),
        role=role,
        password_hash=passwords.hash_password(password),
        must_change_password=True,
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        "user.created",
        actor,
        target_type="user",
        target_id=user.id,
        ip_address=ip,
        email=email,
        role=role.value,
    )
    return user, password


def _active_admins(db: Session) -> int:
    return (
        db.scalar(select(func.count()).where(User.role == Role.ADMIN, User.is_active.is_(True)))
        or 0
    )


def update_user(
    db: Session,
    user: User,
    actor: Actor,
    *,
    role: Role | None = None,
    is_active: bool | None = None,
    display_name: str | None = None,
    ip: str | None = None,
) -> None:
    removes_admin = (
        user.role == Role.ADMIN
        and user.is_active
        and ((role is not None and role != Role.ADMIN) or is_active is False)
    )
    if removes_admin and actor.user_id == user.id:
        raise AccountError("You cannot remove your own administrator access.")
    if removes_admin:
        # Serialize admin removals: two admins demoting each other at the same moment
        # must not both see "two admins left" and leave none.
        db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _ADMIN_CHANGE_LOCK_ID})
        if _active_admins(db) <= 1:
            raise AccountError("At least one active administrator must remain.")
        # Invitations they created end with their administrator access.
        revoked = db.execute(
            update(UserInvite)
            .where(
                UserInvite.created_by_user_id == user.id,
                UserInvite.accepted_at.is_(None),
                UserInvite.revoked_at.is_(None),
            )
            .values(revoked_at=_now())
        ).rowcount
        if revoked:
            audit.record(
                db,
                "invite.revoked",
                actor,
                target_type="user",
                target_id=user.id,
                ip_address=ip,
                reason="creator lost administrator access",
                count=revoked,
            )
    changes: dict[str, object] = {}
    if role is not None and role != user.role:
        changes["role"] = [user.role.value, role.value]
        user.role = role
    if is_active is not None and is_active != user.is_active:
        changes["is_active"] = [user.is_active, is_active]
        user.is_active = is_active
        if not is_active:
            auth_sessions.revoke_all(db, user.id)
    if display_name is not None and display_name.strip() != user.display_name:
        changes["display_name"] = True
        user.display_name = display_name.strip()
    if changes:
        audit.record(
            db,
            "user.updated",
            actor,
            target_type="user",
            target_id=user.id,
            ip_address=ip,
            changes=changes,
        )


def reset_mfa(db: Session, user: User, actor: Actor, ip: str | None = None) -> None:
    """Remove a user's MFA (lost phone). They must set it up again at next login."""
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_last_used_step = None
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    auth_sessions.revoke_all(db, user.id)
    audit.record(db, "mfa.reset", actor, target_type="user", target_id=user.id, ip_address=ip)


def reset_password(db: Session, user: User, actor: Actor, ip: str | None = None) -> str:
    """Set a new temporary password (returned once) and unlock the account."""
    password = temporary_password()
    user.password_hash = passwords.hash_password(password)
    user.must_change_password = True
    user.failed_login_count = 0
    user.locked_until = None
    auth_sessions.revoke_all(db, user.id)
    audit.record(
        db, "user.password_reset", actor, target_type="user", target_id=user.id, ip_address=ip
    )
    return password


def assign_client(
    db: Session, user: User, client_id: uuid.UUID, actor: Actor, ip: str | None = None
) -> bool:
    """True if a new assignment was made."""
    if db.get(ClientAssignment, (user.id, client_id)) is not None:
        return False
    db.add(ClientAssignment(user_id=user.id, client_id=client_id))
    audit.record(
        db,
        "assignment.added",
        actor,
        client_id=client_id,
        target_type="user",
        target_id=user.id,
        ip_address=ip,
    )
    return True


def unassign_client(
    db: Session, user: User, client_id: uuid.UUID, actor: Actor, ip: str | None = None
) -> bool:
    assignment = db.get(ClientAssignment, (user.id, client_id))
    if assignment is None:
        return False
    db.delete(assignment)
    audit.record(
        db,
        "assignment.removed",
        actor,
        client_id=client_id,
        target_type="user",
        target_id=user.id,
        ip_address=ip,
    )
    return True


def assigned_client_ids(db: Session, user_id: uuid.UUID) -> set[uuid.UUID]:
    return set(
        db.scalars(select(ClientAssignment.client_id).where(ClientAssignment.user_id == user_id))
    )
