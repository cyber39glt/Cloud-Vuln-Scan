"""User administration and the audit log. Administrators only."""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import select

from app.api.deps import AdminUser, AppSettings, DbSession, client_ip
from app.auth import onboarding, service
from app.storage import repository as repo
from app.storage.models import AuditEvent, Role, User, UserInvite

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

Ip = Annotated[str | None, Depends(client_ip)]
# Deliberately simple: one "@", no spaces. Mail is never sent to it by the platform.
Email = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, to_lower=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    ),
]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Email
    display_name: DisplayName
    role: Role


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    is_active: bool | None = None
    display_name: DisplayName | None = None


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    role: Role
    is_active: bool
    mfa_enabled: bool
    must_change_password: bool
    locked: bool
    last_login_at: datetime | None
    created_at: datetime
    client_ids: list[uuid.UUID]


class TemporaryPasswordOut(BaseModel):
    user: UserOut
    temporary_password: str
    note: str = (
        "Give this password to the user through a separate, secure channel. It is shown "
        "only once; the user must change it and set up MFA at first login."
    )


class InviteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Email
    display_name: DisplayName
    role: Role


class InviteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    display_name: str
    role: Role
    created_by: str
    created_at: datetime
    expires_at: datetime


class InviteCreated(BaseModel):
    invite: InviteOut
    # Shown once. The dashboard turns it into the link: <site>/invite#<token>
    token: str
    note: str = (
        "Send the link to this person through a channel you trust. It works once and "
        "expires; only its hash is stored, so it cannot be shown again."
    )


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    occurred_at: datetime
    action: str
    outcome: str
    actor_type: str
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    client_id: uuid.UUID | None
    target_type: str | None
    target_id: str | None
    ip_address: str | None
    details: dict[str, Any]


def _out(db: DbSession, user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        must_change_password=user.must_change_password,
        locked=bool(user.locked_until and user.locked_until > datetime.now(UTC)),
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        client_ids=sorted(service.assigned_client_ids(db, user.id)),
    )


def _user(db: DbSession, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise repo.NotFoundError("user not found")
    return user


@router.get("/users")
def list_users(admin: AdminUser, db: DbSession) -> list[UserOut]:
    del admin
    return [_out(db, u) for u in db.scalars(select(User).order_by(User.email))]


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, admin: AdminUser, db: DbSession, ip: Ip) -> TemporaryPasswordOut:
    try:
        user, password = service.create_user(
            db, body.email, body.display_name, body.role, admin.actor, ip
        )
    except service.AccountError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return TemporaryPasswordOut(user=_out(db, user), temporary_password=password)


@router.patch("/users/{user_id}")
def update_user(
    user_id: uuid.UUID, body: UserUpdate, admin: AdminUser, db: DbSession, ip: Ip
) -> UserOut:
    user = _user(db, user_id)
    try:
        service.update_user(
            db,
            user,
            admin.actor,
            role=body.role,
            is_active=body.is_active,
            display_name=body.display_name,
            ip=ip,
        )
    except service.AccountError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _out(db, user)


@router.post("/users/{user_id}/reset-mfa")
def reset_mfa(user_id: uuid.UUID, admin: AdminUser, db: DbSession, ip: Ip) -> UserOut:
    user = _user(db, user_id)
    service.reset_mfa(db, user, admin.actor, ip)
    return _out(db, user)


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: uuid.UUID, admin: AdminUser, db: DbSession, ip: Ip
) -> TemporaryPasswordOut:
    user = _user(db, user_id)
    password = service.reset_password(db, user, admin.actor, ip)
    return TemporaryPasswordOut(user=_out(db, user), temporary_password=password)


@router.put("/users/{user_id}/clients/{client_id}")
def assign_client(
    user_id: uuid.UUID, client_id: uuid.UUID, admin: AdminUser, db: DbSession, ip: Ip
) -> UserOut:
    user = _user(db, user_id)
    repo.get_client(db, client_id)  # 404 if it does not exist
    service.assign_client(db, user, client_id, admin.actor, ip)
    return _out(db, user)


@router.delete("/users/{user_id}/clients/{client_id}")
def unassign_client(
    user_id: uuid.UUID, client_id: uuid.UUID, admin: AdminUser, db: DbSession, ip: Ip
) -> UserOut:
    user = _user(db, user_id)
    repo.get_client(db, client_id)  # unknown client: 404, not a misleading audit entry
    service.unassign_client(db, user, client_id, admin.actor, ip)
    return _out(db, user)


@router.get("/audit-events")
def list_audit_events(
    admin: AdminUser,
    db: DbSession,
    client_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditEventOut]:
    del admin
    query = select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(limit)
    if client_id is not None:
        query = query.where(AuditEvent.client_id == client_id)
    if user_id is not None:
        query = query.where(AuditEvent.actor_user_id == user_id)
    if action is not None:
        query = query.where(AuditEvent.action == action)
    return [AuditEventOut.model_validate(e) for e in db.scalars(query)]


# ------------------------------------------------------------------ invitations (ADR 0024)


@router.get("/invites")
def list_invites(admin: AdminUser, db: DbSession) -> list[InviteOut]:
    del admin
    return [InviteOut.model_validate(i) for i in onboarding.pending_invites(db)]


@router.post("/invites", status_code=status.HTTP_201_CREATED)
def create_invite(
    body: InviteCreate, admin: AdminUser, db: DbSession, settings: AppSettings, ip: Ip
) -> InviteCreated:
    try:
        invite, token = onboarding.create_invite(
            db, body.email, body.display_name, body.role, admin.actor, settings, ip
        )
    except service.AccountError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return InviteCreated(invite=InviteOut.model_validate(invite), token=token)


@router.delete("/invites/{invite_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invite(invite_id: uuid.UUID, admin: AdminUser, db: DbSession, ip: Ip) -> None:
    invite = db.get(UserInvite, invite_id)
    if invite is None:
        raise repo.NotFoundError("invite not found")
    try:
        onboarding.revoke_invite(db, invite, admin.actor, ip)
    except service.AccountError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
