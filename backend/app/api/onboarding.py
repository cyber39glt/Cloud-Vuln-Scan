"""Public endpoints for getting into the platform without public sign-up (ADR 0024).

    GET  /setup              is first-run setup still open?
    POST /setup              create the first administrator (needs the setup code)
    POST /invites/lookup     who is this invitation for?  (token in the body)
    POST /invites/accept     choose a password for an invited account

The invitation token travels in the link's #fragment, which browsers never send to
the server, and then in a JSON body: it never appears in a URL the server logs.
A successful setup or acceptance starts a login session that still needs MFA set up,
exactly like a first login. Attempts share the login rate limit.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.api.admin import DisplayName, Email
from app.api.auth import LoginResult, error_response, set_session_cookie
from app.api.deps import AppSettings, DbSession, client_ip
from app.auth import audit, onboarding
from app.auth import sessions as auth_sessions
from app.auth.ratelimit import login_limiter
from app.core.config import Settings
from app.storage.models import Role, User

router = APIRouter(prefix="/api/v1", tags=["onboarding"])

Ip = Annotated[str | None, Depends(client_ip)]
Token = Annotated[str, StringConstraints(min_length=20, max_length=128)]
Password = Annotated[str, Field(min_length=1, max_length=1024)]


class SetupStatus(BaseModel):
    needed: bool


class SetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    setup_code: str = Field(min_length=1, max_length=64)
    email: Email
    display_name: DisplayName
    password: Password


class InviteLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: Token


class InviteAccept(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: Token
    password: Password


class InviteInfo(BaseModel):
    email: str
    display_name: str
    role: Role
    consultancy: str


def _too_many(db: DbSession, ip: str | None, action: str) -> JSONResponse | None:
    if login_limiter.allow(ip or "unknown"):
        return None
    audit.record(db, action, audit.ANONYMOUS, outcome="rate_limited", ip_address=ip)
    return error_response(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Try again later.")


def _signed_in(db: DbSession, user: User, settings: Settings) -> JSONResponse:
    """Start the session that continues with MFA setup (as at a first login)."""
    token = auth_sessions.create(db, user, mfa_verified=False, settings=settings)
    response = JSONResponse(LoginResult(mfa_enrolled=False, next_step="mfa_setup").model_dump())
    set_session_cookie(response, token, settings)
    return response


@router.get("/setup")
def setup_status(db: DbSession) -> SetupStatus:
    return SetupStatus(needed=onboarding.setup_needed(db))


@router.post("/setup", response_model=LoginResult)
def complete_setup(
    body: SetupRequest, db: DbSession, settings: AppSettings, ip: Ip
) -> JSONResponse:
    if (limited := _too_many(db, ip, "setup.completed")) is not None:
        return limited
    try:
        user = onboarding.complete_setup(
            db, settings, body.setup_code, body.email, body.display_name, body.password, ip
        )
    except onboarding.OnboardingError as exc:
        # Returned, not raised: the failed attempt stays in the audit log.
        return error_response(status.HTTP_400_BAD_REQUEST, str(exc))
    return _signed_in(db, user, settings)


@router.post("/invites/lookup")
def lookup_invite(body: InviteLookup, db: DbSession, settings: AppSettings, ip: Ip) -> JSONResponse:
    if (limited := _too_many(db, ip, "invite.lookup")) is not None:
        return limited
    invite = onboarding.find_pending_invite(db, body.token)
    if invite is None:
        return error_response(status.HTTP_404_NOT_FOUND, onboarding.INVALID_INVITE)
    info = InviteInfo(
        email=invite.email,
        display_name=invite.display_name,
        role=invite.role,
        consultancy=settings.consultancy_name,
    )
    return JSONResponse(info.model_dump(mode="json"))


@router.post("/invites/accept", response_model=LoginResult)
def accept_invite(body: InviteAccept, db: DbSession, settings: AppSettings, ip: Ip) -> JSONResponse:
    if (limited := _too_many(db, ip, "invite.accepted")) is not None:
        return limited
    try:
        user = onboarding.accept_invite(db, body.token, body.password, ip)
    except onboarding.OnboardingError as exc:
        return error_response(status.HTTP_400_BAD_REQUEST, str(exc))
    return _signed_in(db, user, settings)
