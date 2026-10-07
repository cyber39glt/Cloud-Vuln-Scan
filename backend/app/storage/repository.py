"""Client-scoped data access.

Every function that touches client data takes `client_id` and filters by it. Asking
for a record that belongs to another client behaves exactly like asking for one that
does not exist (NotFoundError), so a caller cannot even learn that it exists.
"""

import hashlib
import json
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.enums import Provider
from app.domain.findings import AssessmentResult
from app.providers.aws.session import generate_external_id
from app.storage.models import (
    Assessment,
    AssessmentStatus,
    Client,
    CloudConnection,
    FindingRecord,
    ScanRun,
    ScanStatus,
)

logger = logging.getLogger(__name__)


class NotFoundError(LookupError):
    """The record does not exist, or belongs to another client."""


class IntegrityViolation(RuntimeError):
    """A stored scan result no longer matches its recorded hash."""


def result_hash(result_json: dict[str, Any]) -> str:
    """SHA-256 over a canonical JSON form (sorted keys, no whitespace), so the same
    content always produces the same hash regardless of storage formatting."""
    canonical = json.dumps(result_json, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ clients


def create_client(session: Session, name: str) -> Client:
    client = Client(name=name.strip())
    session.add(client)
    session.flush()
    logger.info("client created", extra={"client_id": str(client.id)})
    return client


def list_clients(session: Session) -> list[Client]:
    # Unscoped by design: in M9 this becomes "clients assigned to the current user".
    return list(session.scalars(select(Client).order_by(Client.name)))


def find_client(session: Session, name_or_id: str) -> Client:
    """Look a client up by exact name or by ID."""
    try:
        client = session.get(Client, uuid.UUID(name_or_id))
    except ValueError:
        client = session.scalar(select(Client).where(Client.name == name_or_id.strip()))
    if client is None:
        raise NotFoundError("client not found")
    return client


# ------------------------------------------------------------------ connections


def get_or_create_aws_connection(
    session: Session, client_id: uuid.UUID, account_id: str, consultancy_name: str
) -> CloudConnection:
    """One connection per client and AWS account, with its own ExternalId."""
    connection = session.scalar(
        select(CloudConnection).where(
            CloudConnection.client_id == client_id,
            CloudConnection.provider == Provider.AWS,
            CloudConnection.account_id == account_id,
        )
    )
    if connection is None:
        connection = CloudConnection(
            client_id=client_id,
            provider=Provider.AWS,
            account_id=account_id,
            external_id=generate_external_id(consultancy_name),
        )
        session.add(connection)
        session.flush()
        logger.info(
            "cloud connection created",
            extra={"client_id": str(client_id), "connection_id": str(connection.id)},
        )
    return connection


def get_or_create_azure_connection(
    session: Session, client_id: uuid.UUID, tenant_id: str, subscription_id: str
) -> CloudConnection:
    """One connection per client and Azure subscription. No secret is stored: the
    platform's own app identity is used, scoped to the client's tenant."""
    subscription_id = subscription_id.lower()
    connection = session.scalar(
        select(CloudConnection).where(
            CloudConnection.client_id == client_id,
            CloudConnection.provider == Provider.AZURE,
            CloudConnection.account_id == subscription_id,
        )
    )
    if connection is None:
        connection = CloudConnection(
            client_id=client_id,
            provider=Provider.AZURE,
            account_id=subscription_id,
            tenant_id=tenant_id.lower(),
        )
        session.add(connection)
        session.flush()
        logger.info(
            "cloud connection created",
            extra={"client_id": str(client_id), "connection_id": str(connection.id)},
        )
    elif connection.tenant_id != tenant_id.lower():
        raise ValueError("this subscription is already registered with a different tenant")
    return connection


def get_connection(
    session: Session, client_id: uuid.UUID, provider: Provider, account_id: str
) -> CloudConnection:
    connection = session.scalar(
        select(CloudConnection).where(
            CloudConnection.client_id == client_id,
            CloudConnection.provider == provider,
            CloudConnection.account_id == account_id,
        )
    )
    if connection is None:
        raise NotFoundError("no connection for this client and account")
    return connection


# ------------------------------------------------------------------ assessments + scans


def create_assessment(
    session: Session, client_id: uuid.UUID, connection_id: uuid.UUID, name: str
) -> Assessment:
    assessment = Assessment(client_id=client_id, connection_id=connection_id, name=name.strip())
    session.add(assessment)
    session.flush()
    return assessment


def get_or_create_assessment(
    session: Session, client_id: uuid.UUID, connection_id: uuid.UUID, name: str
) -> Assessment:
    """Repeat scans with the same assessment name add scan runs to that assessment."""
    assessment = session.scalar(
        select(Assessment).where(
            Assessment.client_id == client_id,
            Assessment.connection_id == connection_id,
            Assessment.name == name.strip(),
        )
    )
    return assessment or create_assessment(session, client_id, connection_id, name)


def list_assessments(session: Session, client_id: uuid.UUID) -> list[Assessment]:
    return list(
        session.scalars(
            select(Assessment)
            .where(Assessment.client_id == client_id)
            .order_by(Assessment.created_at.desc())
        )
    )


def list_scan_runs(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID
) -> list[ScanRun]:
    return list(
        session.scalars(
            select(ScanRun)
            .where(ScanRun.client_id == client_id, ScanRun.assessment_id == assessment_id)
            .order_by(ScanRun.started_at.desc())
        )
    )


def save_scan_result(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID, result: AssessmentResult
) -> ScanRun:
    """Store a completed scan: the frozen dataset + hash, and one row per finding."""
    assessment = session.scalar(
        select(Assessment).where(Assessment.id == assessment_id, Assessment.client_id == client_id)
    )
    if assessment is None:
        raise NotFoundError("assessment not found")

    result_json = result.model_dump(mode="json")
    scan = ScanRun(
        client_id=client_id,
        assessment_id=assessment_id,
        status=ScanStatus.COMPLETED,
        provider=result.provider,
        account_id=result.account_id,
        regions=list(result.regions),
        engine_version=result.engine_version,
        started_at=result.started_at,
        completed_at=result.completed_at,
        result=result_json,
        result_sha256=result_hash(result_json),
    )
    session.add(scan)
    session.flush()

    session.add_all(
        FindingRecord(
            client_id=client_id,
            scan_run_id=scan.id,
            fingerprint=finding.finding_id,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            severity=finding.severity,
            category=finding.category,
            provider=finding.provider,
            account_id=finding.account_id,
            region=finding.region,
            resource_id=finding.resource_id,
            resource_name=finding.resource_name,
            title=finding.title,
            detected_at=finding.detected_at,
            data=finding_json,
        )
        for finding, finding_json in zip(result.findings, result_json["findings"], strict=True)
    )
    if assessment.status == AssessmentStatus.DRAFT:
        assessment.status = AssessmentStatus.IN_REVIEW
    session.flush()
    logger.info(
        "scan result saved",
        extra={
            "client_id": str(client_id),
            "scan_run_id": str(scan.id),
            "findings": len(result.findings),
        },
    )
    return scan


def load_scan_result(
    session: Session, client_id: uuid.UUID, scan_run_id: uuid.UUID
) -> AssessmentResult:
    """Read a stored scan back as an AssessmentResult, verifying its hash first."""
    scan = session.scalar(
        select(ScanRun).where(ScanRun.id == scan_run_id, ScanRun.client_id == client_id)
    )
    if scan is None:
        raise NotFoundError("scan not found")
    if result_hash(scan.result) != scan.result_sha256:
        logger.error("stored scan failed integrity check", extra={"scan_run_id": str(scan.id)})
        raise IntegrityViolation("stored scan result does not match its recorded hash")
    return AssessmentResult.model_validate(scan.result)
