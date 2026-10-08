"""Login, MFA, logout and password change.

Login is two steps, and MFA is mandatory for everyone:

    POST /auth/login {email, password}       -> pending session cookie
      first time:  POST /auth/mfa/setup      -> secret + otpauth link (for the app)
                   POST /auth/mfa/activate   -> recovery codes (shown once); logged in
      afterwards:  POST /auth/mfa/verify     -> logged in
    POST /auth/password  (required first with a temporary password)
    POST /auth/logout

Failures that must be remembered (counters, lockout, audit) are returned as plain
JSON responses rather than raised, so the request's transaction is committed.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import (
    AnySession,
    AppSettings,
    DbSession,
    Principal,
    VerifiedUser,
    client_ip,
)
from app.auth import audit, service
from app.auth import sessions as auth_sessions
from app.auth.ratelimit import login_limiter
from app.core.config import Settings
from app.storage.models import Role

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

Ip = Annotated[str | None, Depends(client_ip)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Request):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class LoginResult(BaseModel):
    mfa_enrolled: bool
    next_step: str  # "mfa_setup" or "mfa_verify"


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class CodeRequest(_Request):
    code: str = Field(min_length=6, max_length=10)


class VerifyRequest(_Request):
    code: str | None = Field(default=None, min_length=6, max_length=10)
    recovery_code: str | None = Field(default=None, min_length=8, max_length=32)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]
    note: str = "Store these somewhere safe. Each works once. They are not shown again."


class PasswordChange(_Request):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class MeOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: Role
    must_change_password: bool
    mfa_enabled: bool
    consultancy: str


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        auth_sessions.cookie_name(settings),
        token,
        httponly=True,  # not readable by JavaScript
        secure=settings.session_cookie_secure,
        samesite="strict",  # never sent with requests started by other sites
        path="/",
    )


def _clear_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        auth_sessions.cookie_name(settings),
        path="/",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="strict",
    )


def error_response(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status_code)


def _me(principal: Principal, settings: Settings) -> MeOut:
    user = principal.user
    return MeOut(
        id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        must_change_password=user.must_change_password,
        mfa_enabled=user.mfa_enabled,
        consultancy=settings.consultancy_name,
    )


@router.post("/login", response_model=LoginResult)
def login(body: LoginRequest, db: DbSession, settings: AppSettings, ip: Ip) -> Response:
    if not login_limiter.allow(ip or "unknown"):
        audit.record(db, "auth.rate_limited", audit.ANONYMOUS, outcome="denied", ip_address=ip)
        return error_response(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Try again later."
        )
    user = service.authenticate(db, body.email, body.password, settings, ip)
    if user is None:
        return error_response(status.HTTP_401_UNAUTHORIZED, service.GENERIC_LOGIN_ERROR)
    token = auth_sessions.create(db, user, mfa_verified=False, settings=settings)
    result = LoginResult(
        mfa_enrolled=user.mfa_enabled,
        next_step="mfa_verify" if user.mfa_enabled else "mfa_setup",
    )
    response = JSONResponse(result.model_dump())
    set_session_cookie(response, token, settings)
    return response


@router.post("/mfa/setup")
def mfa_setup(principal: AnySession, db: DbSession, settings: AppSettings, ip: Ip) -> Response:
    if principal.session.mfa_verified and principal.user.mfa_enabled:
        return error_response(status.HTTP_409_CONFLICT, "MFA is already set up.")
    try:
        setup = service.start_enrollment(db, principal.user, settings, ip)
    except service.AccountError as exc:
        return error_response(status.HTTP_409_CONFLICT, str(exc))
    return JSONResponse(
        MfaSetupOut(secret=setup.secret, otpauth_uri=setup.otpauth_uri).model_dump()
    )


@router.post("/mfa/activate", response_model=RecoveryCodesOut)
def mfa_activate(
    body: CodeRequest, principal: AnySession, db: DbSession, settings: AppSettings, ip: Ip
) -> Response:
    try:
        codes = service.complete_enrollment(
            db, principal.session, principal.user, body.code, settings, ip
        )
    except service.AccountError as exc:
        return error_response(status.HTTP_409_CONFLICT, str(exc))
    if codes is None:
        return error_response(
            status.HTTP_401_UNAUTHORIZED, "The code is not valid. Try the next one."
        )
    service.finish_login(db, principal.user)
    token = auth_sessions.rotate(
        db, principal.session, principal.user, mfa_verified=True, settings=settings
    )
    audit.record(db, "auth.login", principal.actor, ip_address=ip)
    response = JSONResponse(RecoveryCodesOut(recovery_codes=codes).model_dump())
    set_session_cookie(response, token, settings)
    return response


@router.post("/mfa/verify", status_code=status.HTTP_204_NO_CONTENT)
def mfa_verify(
    body: VerifyRequest, principal: AnySession, db: DbSession, settings: AppSettings, ip: Ip
) -> Response:
    if (body.code is None) == (body.recovery_code is None):
        return error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Send either code or recovery_code."
        )
    if principal.session.mfa_verified:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    ok = service.verify_second_factor(
        db,
        principal.session,
        principal.user,
        settings,
        ip,
        code=body.code,
        recovery_code=body.recovery_code,
    )
    if not ok:
        return error_response(status.HTTP_401_UNAUTHORIZED, "The code is not valid.")
    service.finish_login(db, principal.user)
    token = auth_sessions.rotate(
        db, principal.session, principal.user, mfa_verified=True, settings=settings
    )
    audit.record(db, "auth.login", principal.actor, ip_address=ip)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    set_session_cookie(response, token, settings)
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(principal: AnySession, db: DbSession, settings: AppSettings, ip: Ip) -> Response:
    auth_sessions.revoke(db, principal.session)
    audit.record(db, "auth.logout", principal.actor, ip_address=ip)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_cookie(response, settings)
    return response


@router.get("/me")
def me(principal: VerifiedUser, settings: AppSettings) -> MeOut:
    return _me(principal, settings)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChange,
    principal: VerifiedUser,
    db: DbSession,
    settings: AppSettings,
    ip: Ip,
) -> Response:
    problem = service.change_password(
        db, principal.user, body.current_password, body.new_password, ip
    )
    if problem is not None:
        return error_response(status.HTTP_400_BAD_REQUEST, problem)
    # Every session of this user ends; this browser gets a fresh one.
    auth_sessions.revoke_all(db, principal.user.id)
    token = auth_sessions.create(db, principal.user, mfa_verified=True, settings=settings)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    set_session_cookie(response, token, settings)
    return response


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesOut)
def new_recovery_codes(
    body: CodeRequest, principal: VerifiedUser, db: DbSession, settings: AppSettings, ip: Ip
) -> Response:
    """Replace all recovery codes. Requires a current authenticator code."""
    if not service.verify_second_factor(
        db, principal.session, principal.user, settings, ip, code=body.code
    ):
        return error_response(status.HTTP_401_UNAUTHORIZED, "The code is not valid.")
    codes = service.regenerate_recovery_codes(db, principal.user, ip)
    return JSONResponse(RecoveryCodesOut(recovery_codes=codes).model_dump())
