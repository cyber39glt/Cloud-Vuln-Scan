"""Request and response bodies of the data API.

Requests forbid unknown fields and validate formats strictly. Responses list their
fields explicitly, so a new database column is never exposed by accident.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.domain.enums import Provider, ScanStage
from app.storage.models import AssessmentStatus, JobStatus

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
AwsAccountId = Annotated[str, StringConstraints(pattern=r"^[0-9]{12}$")]  # ASCII digits only
# Patterns are checked before lower-casing, so they accept both cases.
Guid = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        pattern=r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$",
    ),
]
# Region names (AWS "eu-west-2", Azure "uksouth"): letters, digits and hyphens only.
Region = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, to_lower=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{1,31}$"
    ),
]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _Response(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ clients


class ClientCreate(_Request):
    name: Name


class ClientOut(_Response):
    id: uuid.UUID
    name: str
    created_at: datetime


# ------------------------------------------------------------------ connections


class AwsConnectionCreate(_Request):
    account_id: AwsAccountId


class AzureConnectionCreate(_Request):
    tenant_id: Guid
    subscription_id: Guid


class ConnectionOut(_Response):
    id: uuid.UUID
    provider: Provider
    account_id: str
    # AWS: not a secret, the client puts it in their role's trust policy.
    external_id: str | None
    tenant_id: str | None
    created_at: datetime


class AwsSetup(BaseModel):
    """What the client needs to create the read-only role (docs/aws-connection.md)."""

    role_name: str
    external_id: str
    template: str = "infra/aws/client-onboarding-role.yaml"


class Onboarding(BaseModel):
    """What the client's administrator does once to grant read-only access."""

    provider: Provider
    # AWS
    role_name: str | None = None
    external_id: str | None = None
    template: str | None = None
    # The exact read permissions granted (AWS, least-privilege default).
    permissions: list[str] = []
    # Azure: a custom role with exactly the read permissions the checks use
    # (recommended), or the broader built-in roles as a fallback.
    admin_consent_url: str | None = None
    role_definition: dict[str, Any] | None = None
    role_commands: list[str] = []
    fallback_role_commands: list[str] = []
    guide: str


class AwsConnectionOut(BaseModel):
    connection: ConnectionOut
    setup: AwsSetup


# ------------------------------------------------------------------ assessments


class AssessmentCreate(_Request):
    connection_id: uuid.UUID
    name: Name


class AssessmentOut(_Response):
    id: uuid.UUID
    connection_id: uuid.UUID
    name: str
    status: AssessmentStatus
    created_at: datetime


class ScanRunOut(BaseModel):
    id: uuid.UUID
    provider: Provider
    account_id: str
    regions: list[str]
    started_at: datetime
    completed_at: datetime
    findings: int


class FinalizationSummary(BaseModel):
    id: uuid.UUID
    scan_run_id: uuid.UUID
    finalized_at: datetime
    finalized_by: str
    report_sha256: str


class AssessmentDetail(AssessmentOut):
    scans: list[ScanRunOut]
    # Set while the assessment is finalized: the snapshot every output uses.
    finalization: FinalizationSummary | None = None


# ------------------------------------------------------------------ scan jobs


class ScanRequest(_Request):
    """`regions`: limit the scan to these regions; omit (or null) for all."""

    regions: list[Region] | None = Field(default=None, min_length=1, max_length=50)


class ScanJobOut(_Response):
    id: uuid.UUID
    assessment_id: uuid.UUID
    status: JobStatus
    stage: ScanStage
    regions: list[str] | None
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_code: str | None
    error_message: str | None
    scan_run_id: uuid.UUID | None
