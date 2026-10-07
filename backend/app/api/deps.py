"""Shared request dependencies: database session, the current operator, client access.

Every data endpoint depends on `client_scope` (or `current_operator` for the client
list). That is the single place where M9 adds real authentication and the check
"is this user assigned to this client?", without changing any endpoint.

Until M9 there are no user accounts. The data API therefore works ONLY when
APP_ENV is development or test (on a developer's own machine, bound to 127.0.0.1)
and refuses every request in production (ADR 0019).
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import get_sessionmaker
from app.storage import repository as repo
from app.storage.models import Client


def get_db() -> Iterator[Session]:
    """One transaction per request: committed if the endpoint succeeds, rolled back
    if it raises."""
    with get_sessionmaker().begin() as session:
        yield session


@dataclass(frozen=True)
class Operator:
    """Who is making the request. In M9 this becomes an authenticated user with a
    role (Admin / Consultant) and client assignments."""

    name: str
    is_development_operator: bool


DEVELOPMENT_OPERATOR = Operator(name="local-developer", is_development_operator=True)


def current_operator(settings: Annotated[Settings, Depends(get_settings)]) -> Operator:
    if settings.app_env in ("development", "test"):
        return DEVELOPMENT_OPERATOR
    # Fail closed: without user authentication, nobody may use the data API.
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="The data API is disabled until user authentication is available.",
    )


DbSession = Annotated[Session, Depends(get_db)]
CurrentOperator = Annotated[Operator, Depends(current_operator)]


def client_scope(client_id: uuid.UUID, db: DbSession, operator: CurrentOperator) -> Client:
    """The client named in the URL, if the operator may access it. A client the
    operator may not access looks exactly like one that does not exist (404)."""
    del operator  # M9: check the operator's client assignment here.
    return repo.get_client(db, client_id)


ClientScope = Annotated[Client, Depends(client_scope)]
