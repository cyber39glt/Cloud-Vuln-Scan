"""Clients and their cloud connections."""

from fastapi import APIRouter, HTTPException, status

from app.api.deps import ClientScope, CurrentOperator, DbSession
from app.api.schemas import (
    AwsConnectionCreate,
    AwsConnectionOut,
    AwsSetup,
    AzureConnectionCreate,
    ClientCreate,
    ClientOut,
    ConnectionOut,
)
from app.core.config import get_settings
from app.storage import repository as repo

router = APIRouter(prefix="/api/v1/clients", tags=["clients"])


@router.get("")
def list_clients(db: DbSession, operator: CurrentOperator) -> list[ClientOut]:
    del operator  # M9: only the clients assigned to this user (all for Admins).
    return [ClientOut.model_validate(c) for c in repo.list_clients(db)]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_client(body: ClientCreate, db: DbSession, operator: CurrentOperator) -> ClientOut:
    del operator  # M9: Admins only.
    if any(c.name.lower() == body.name.lower() for c in repo.list_clients(db)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A client with this name already exists.")
    return ClientOut.model_validate(repo.create_client(db, body.name))


@router.get("/{client_id}")
def get_client(client: ClientScope) -> ClientOut:
    return ClientOut.model_validate(client)


@router.get("/{client_id}/connections")
def list_connections(client: ClientScope, db: DbSession) -> list[ConnectionOut]:
    return [ConnectionOut.model_validate(c) for c in repo.list_connections(db, client.id)]


@router.post("/{client_id}/connections/aws", status_code=status.HTTP_201_CREATED)
def connect_aws(body: AwsConnectionCreate, client: ClientScope, db: DbSession) -> AwsConnectionOut:
    """Register an AWS account. Idempotent: the same account returns the same
    ExternalId. Nothing is contacted in AWS."""
    settings = get_settings()
    connection = repo.get_or_create_aws_connection(
        db, client.id, body.account_id, settings.consultancy_name
    )
    return AwsConnectionOut(
        connection=ConnectionOut.model_validate(connection),
        setup=AwsSetup(
            role_name=settings.aws_assessment_role_name,
            external_id=connection.external_id or "",
        ),
    )


@router.post("/{client_id}/connections/azure", status_code=status.HTTP_201_CREATED)
def connect_azure(body: AzureConnectionCreate, client: ClientScope, db: DbSession) -> ConnectionOut:
    """Register an Azure subscription. No secret is stored. Nothing is contacted in
    Azure; the client still grants consent and roles (docs/azure-connection.md)."""
    try:
        connection = repo.get_or_create_azure_connection(
            db, client.id, body.tenant_id, body.subscription_id
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return ConnectionOut.model_validate(connection)
