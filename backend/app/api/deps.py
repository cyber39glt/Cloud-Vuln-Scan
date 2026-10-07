"""Shared request dependencies: database session, authentication, client access.

Every data endpoint depends on `client_scope` (client-owned data) or on
`current_user` / `admin_user`. These are the single place where authentication and
authorization are enforced (ADR 0009, ADR 0020); a test checks every route uses one.

    no / invalid session cookie        -> 401
    password OK but MFA not done        -> 401 (only the MFA endpoints accept it)
    temporary password not yet changed  -> 403 (only password change / logout / me)
    Consultant, client not assigned     -> 404 (indistinguishable from "does not exist")
    Consultant on an admin endpoint     -> 403
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth import sessions as auth_sessions
from app.auth.audit import Actor
from app.core.config import Settings, get_settings
from app.core.database import get_sessionmaker
from app.storage import repository as repo
from app.storage.models import Client, ClientAssignment, Role, User, UserSession


def get_db() -> Iterator[Session]:
    """One transaction per request: committed if the endpoint succeeds, rolled back
    if it raises."""
    with get_sessionmaker().begin() as session:
        yield session


DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def client_ip(request: Request) -> str | None:
    # The direct peer. Behind a reverse proxy this needs the proxy's trusted header;
    # configured when hosting is chosen (M14).
    return request.client.host if request.client else None


@dataclass(frozen=True)
class Principal:
    """The authenticated user making the request."""

    user: User
    session: UserSession

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    @property
    def is_admin(self) -> bool:
        return self.user.role == Role.ADMIN

    @property
    def actor(self) -> Actor:
        return Actor("user", self.user.id, self.user.email)


def _unauthenticated() -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Not logged in.", headers={"WWW-Authenticate": "Session"}
    )


def any_session(request: Request, db: DbSession, settings: AppSettings) -> Principal:
    """A live session, including one still waiting for MFA. For the MFA endpoints only."""
    found = auth_sessions.resolve(
        db, request.cookies.get(auth_sessions.cookie_name(settings)), settings
    )
    if found is None:
        raise _unauthenticated()
    session, user = found
    return Principal(user, session)


AnySession = Annotated[Principal, Depends(any_session)]


def verified_user(principal: AnySession) -> Principal:
    """Password AND MFA done. May still have to change a temporary password."""
    if not principal.session.mfa_verified:
        raise _unauthenticated()
    return principal


VerifiedUser = Annotated[Principal, Depends(verified_user)]


def current_user(principal: VerifiedUser) -> Principal:
    """A fully logged-in user who may use the platform."""
    if principal.user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Change your temporary password first.")
    return principal


CurrentUser = Annotated[Principal, Depends(current_user)]


def admin_user(principal: CurrentUser) -> Principal:
    if not principal.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access is required.")
    return principal


AdminUser = Annotated[Principal, Depends(admin_user)]


def can_access_client(db: Session, principal: Principal, client_id: uuid.UUID) -> bool:
    if principal.is_admin:
        return True
    return db.get(ClientAssignment, (principal.id, client_id)) is not None


def client_scope(client_id: uuid.UUID, db: DbSession, principal: CurrentUser) -> Client:
    """The client named in the URL, if the user may access it. A client the user may
    not access looks exactly like one that does not exist (404)."""
    if not can_access_client(db, principal, client_id):
        raise repo.NotFoundError("client not found")
    return repo.get_client(db, client_id)


ClientScope = Annotated[Client, Depends(client_scope)]
