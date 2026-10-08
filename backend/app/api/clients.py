"""Clients and their cloud connections."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app import policies
from app.api.deps import AdminUser, ClientScope, CurrentUser, DbSession, client_ip
from app.api.schemas import (
    AwsConnectionCreate,
    AwsConnectionOut,
    AwsSetup,
    AzureConnectionCreate,
    ClientCreate,
    ClientOut,
    ConnectionOut,
    Onboarding,
)
from app.auth import audit, service
from app.core.config import get_settings
from app.domain.enums import Provider
from app.providers.azure.session import admin_consent_url
from app.storage import repository as repo

router = APIRouter(prefix="/api/v1/clients", tags=["clients"])

Ip = Annotated[str | None, Depends(client_ip)]


@router.get("")
def list_clients(db: DbSession, user: CurrentUser) -> list[ClientOut]:
    """Admins see every client; Consultants only those assigned to them."""
    clients = repo.list_clients(db)
    if not user.is_admin:
        allowed = service.assigned_client_ids(db, user.id)
        clients = [c for c in clients if c.id in allowed]
    return [ClientOut.model_validate(c) for c in clients]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_client(body: ClientCreate, db: DbSession, admin: AdminUser, ip: Ip) -> ClientOut:
    if any(c.name.lower() == body.name.lower() for c in repo.list_clients(db)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A client with this name already exists.")
    client = repo.create_client(db, body.name)
    audit.record(db, "client.created", admin.actor, client_id=client.id, ip_address=ip)
    return ClientOut.model_validate(client)


@router.get("/{client_id}")
def get_client(client: ClientScope) -> ClientOut:
    return ClientOut.model_validate(client)


@router.get("/{client_id}/connections")
def list_connections(client: ClientScope, db: DbSession) -> list[ConnectionOut]:
    return [ConnectionOut.model_validate(c) for c in repo.list_connections(db, client.id)]


@router.get("/{client_id}/connections/{connection_id}/onboarding")
def onboarding(connection_id: uuid.UUID, client: ClientScope, db: DbSession) -> Onboarding:
    """The one-time steps the client performs. Nothing is contacted in the cloud."""
    settings = get_settings()
    connection = repo.get_connection_by_id(db, client.id, connection_id)
    if connection.provider == Provider.AWS:
        return Onboarding(
            provider=Provider.AWS,
            role_name=settings.aws_assessment_role_name,
            external_id=connection.external_id,
            template="infra/aws/client-onboarding-role.yaml",
            permissions=policies.aws_actions(),
            guide="docs/aws-connection.md",
        )
    app_id = settings.azure_client_id or None
    return Onboarding(
        provider=Provider.AZURE,
        admin_consent_url=admin_consent_url(connection.tenant_id or "", app_id) if app_id else None,
        role_definition=policies.azure_role(settings.consultancy_name, connection.account_id),
        role_commands=policies.azure_role_commands(
            settings.consultancy_name, connection.account_id, app_id or "<platform app ID>"
        ),
        fallback_role_commands=policies.azure_builtin_role_commands(
            connection.account_id, app_id or "<platform app ID>"
        ),
        guide="docs/azure-connection.md",
    )


@router.post("/{client_id}/connections/aws", status_code=status.HTTP_201_CREATED)
def connect_aws(
    body: AwsConnectionCreate, client: ClientScope, db: DbSession, user: CurrentUser, ip: Ip
) -> AwsConnectionOut:
    """Register an AWS account. Idempotent: the same account returns the same
    ExternalId. Nothing is contacted in AWS."""
    settings = get_settings()
    connection = repo.get_or_create_aws_connection(
        db, client.id, body.account_id, settings.consultancy_name
    )
    audit.record(
        db,
        "connection.registered",
        user.actor,
        client_id=client.id,
        target_type="connection",
        target_id=connection.id,
        ip_address=ip,
        provider="aws",
    )
    return AwsConnectionOut(
        connection=ConnectionOut.model_validate(connection),
        setup=AwsSetup(
            role_name=settings.aws_assessment_role_name,
            external_id=connection.external_id or "",
        ),
    )


@router.post("/{client_id}/connections/azure", status_code=status.HTTP_201_CREATED)
def connect_azure(
    body: AzureConnectionCreate, client: ClientScope, db: DbSession, user: CurrentUser, ip: Ip
) -> ConnectionOut:
    """Register an Azure subscription. No secret is stored. Nothing is contacted in
    Azure; the client still grants consent and roles (docs/azure-connection.md)."""
    try:
        connection = repo.get_or_create_azure_connection(
            db, client.id, body.tenant_id, body.subscription_id
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(
        db,
        "connection.registered",
        user.actor,
        client_id=client.id,
        target_type="connection",
        target_id=connection.id,
        ip_address=ip,
        provider="azure",
    )
    return ConnectionOut.model_validate(connection)
