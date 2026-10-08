"""Database tables (SQLAlchemy ORM).

Client separation is enforced BY THE DATABASE, not only by application code:
every client-owned table carries `client_id`, and child rows reference their parent
with a composite foreign key on (parent id, client_id). PostgreSQL therefore rejects
any row that would link one client's data to another client's record.

    clients
      └─ cloud_connections   (AWS account + ExternalId, or Azure tenant + subscription)
           └─ assessments
                ├─ scan_jobs (queue: requested → running → succeeded/failed; progress)
                └─ scan_runs (frozen snapshot of the full AssessmentResult + SHA-256)
                     └─ findings (queryable copy of each finding, for dashboards)
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    MetaData,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.domain.enums import Category, Provider, ScanStage, Severity

# JSONB on PostgreSQL (indexable, compact); plain JSON elsewhere.
JsonType = JSON().with_variant(JSONB(), "postgresql")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _enum(enum_cls: type[StrEnum], name: str) -> Enum:
    # Stored as text with a CHECK constraint: readable in the database, and adding
    # a value later is a simple migration.
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda e: [m.value for m in e],
    )


class AssessmentStatus(StrEnum):
    DRAFT = "draft"  # created, never scanned
    IN_REVIEW = "in_review"  # at least one scan saved; consultant reviewing
    FINALIZED = "finalized"  # locked for reporting (M12)


class ReviewStatus(StrEnum):
    """A consultant's decision about a finding (ADR 0007)."""

    OPEN = "open"  # not reviewed yet
    CONFIRMED = "confirmed"  # reviewed: a real issue, reported
    FALSE_POSITIVE = "false_positive"  # not a real issue: excluded from the report body
    ACCEPTED_RISK = "accepted_risk"  # real, but the client accepts it: reported separately


# Decisions that must be explained in writing.
REVIEW_STATUSES_NEEDING_JUSTIFICATION = (ReviewStatus.FALSE_POSITIVE, ReviewStatus.ACCEPTED_RISK)


class ScanStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


ACTIVE_JOB_STATUSES = (JobStatus.QUEUED, JobStatus.RUNNING)


class Base(DeclarativeBase):
    # Predictable constraint names, so migrations can refer to them reliably.
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_N_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_N_name)s",
            "pk": "pk_%(table_name)s",
        }
    )


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    __table_args__ = (CheckConstraint("length(trim(name)) > 0", name="client_name_not_blank"),)


class CloudConnection(Base):
    __tablename__ = "cloud_connections"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    provider: Mapped[Provider] = mapped_column(_enum(Provider, "provider"))
    account_id: Mapped[str] = mapped_column(String(64))  # AWS account / Azure subscription
    # AWS only. Not a credential on its own, but it must stay unique per connection.
    external_id: Mapped[str | None] = mapped_column(String(1224), unique=True)
    # Azure only: the client's Entra tenant (directory) ID.
    tenant_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    __table_args__ = (
        ForeignKeyConstraint(["client_id"], ["clients.id"], ondelete="CASCADE"),
        UniqueConstraint("client_id", "provider", "account_id"),
        UniqueConstraint("id", "client_id"),  # target for composite foreign keys
        CheckConstraint(
            "provider <> 'azure' OR tenant_id IS NOT NULL", name="azure_requires_tenant"
        ),
    )


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    connection_id: Mapped[uuid.UUID]
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[AssessmentStatus] = mapped_column(
        _enum(AssessmentStatus, "assessment_status"), default=AssessmentStatus.DRAFT
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    __table_args__ = (
        # The connection must belong to the SAME client.
        ForeignKeyConstraint(
            ["connection_id", "client_id"],
            ["cloud_connections.id", "cloud_connections.client_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("id", "client_id"),
        CheckConstraint("length(trim(name)) > 0", name="assessment_name_not_blank"),
    )


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    assessment_id: Mapped[uuid.UUID]
    status: Mapped[ScanStatus] = mapped_column(_enum(ScanStatus, "scan_status"))
    provider: Mapped[Provider] = mapped_column(_enum(Provider, "provider"))
    account_id: Mapped[str] = mapped_column(String(64))
    regions: Mapped[list[str]] = mapped_column(JsonType)
    engine_version: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # The complete AssessmentResult exactly as produced, and its SHA-256 over a
    # canonical JSON form. Reading it back re-checks the hash (tamper evidence).
    result: Mapped[dict[str, Any]] = mapped_column(JsonType)
    result_sha256: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "client_id"],
            ["assessments.id", "assessments.client_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("id", "client_id"),
        CheckConstraint("length(result_sha256) = 64", name="scan_result_hash_length"),
    )


class ScanJob(Base):
    """A request to scan an assessment's cloud account, processed by the worker.

    The queue is this table (ADR 0003): the worker claims the oldest queued job with
    SELECT ... FOR UPDATE SKIP LOCKED, so two workers never run the same job. Error
    messages are plain-language and safe to show; raw exception text is never stored.
    """

    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    assessment_id: Mapped[uuid.UUID]
    status: Mapped[JobStatus] = mapped_column(
        _enum(JobStatus, "job_status"), default=JobStatus.QUEUED
    )
    stage: Mapped[ScanStage] = mapped_column(
        _enum(ScanStage, "job_stage"), default=ScanStage.WAITING
    )
    # None = every enabled region (AWS) / the whole subscription (Azure).
    regions: Mapped[list[str] | None] = mapped_column(JsonType)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Updated regularly while running; a stale heartbeat means the worker died.
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(1000))
    scan_run_id: Mapped[uuid.UUID | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "client_id"],
            ["assessments.id", "assessments.client_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["scan_run_id", "client_id"],
            ["scan_runs.id", "scan_runs.client_id"],
            ondelete="CASCADE",
        ),
        # At most one queued or running scan per assessment: no duplicate parallel
        # scans of the same client account.
        Index(
            "uq_scan_jobs_one_active_per_assessment",
            "assessment_id",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index("ix_scan_jobs_queue", "status", "requested_at"),
        CheckConstraint(
            "status <> 'succeeded' OR scan_run_id IS NOT NULL", name="succeeded_has_scan"
        ),
    )


# ------------------------------------------------------------------ users and access (M9)


class Role(StrEnum):
    ADMIN = "admin"  # every client; manages users and client assignments
    CONSULTANT = "consultant"  # only the clients assigned to them


class User(Base):
    """A consultancy user. `auth_provider` + `external_subject` let a future SSO
    provider (e.g. Entra ID) log users in without changing anything else (ADR 0009)."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True)  # stored lower-case
    display_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[Role] = mapped_column(_enum(Role, "user_role"))
    is_active: Mapped[bool] = mapped_column(default=True)
    auth_provider: Mapped[str] = mapped_column(String(32), default="local")
    external_subject: Mapped[str | None] = mapped_column(String(256))
    # Argon2id hash (algorithm, parameters and salt are inside the string).
    password_hash: Mapped[str | None] = mapped_column(String(256))
    must_change_password: Mapped[bool] = mapped_column(default=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # TOTP: the secret is ENCRYPTED (it must be readable to check codes). The last
    # accepted time step prevents the same code being used twice.
    mfa_enabled: Mapped[bool] = mapped_column(default=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(String(512))
    mfa_last_used_step: Mapped[int | None]
    failed_login_count: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    __table_args__ = (
        CheckConstraint("email = lower(email) AND length(email) > 3", name="email_normalized"),
        CheckConstraint("length(trim(display_name)) > 0", name="display_name_not_blank"),
        CheckConstraint(
            "auth_provider <> 'local' OR password_hash IS NOT NULL", name="local_has_password"
        ),
        CheckConstraint(
            "NOT mfa_enabled OR mfa_secret_encrypted IS NOT NULL", name="mfa_enabled_has_secret"
        ),
    )


class RecoveryCode(Base):
    """One-time MFA recovery codes, stored only as SHA-256 hashes (the codes are long
    random values, so a fast hash is safe)."""

    __tablename__ = "mfa_recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(64))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("user_id", "code_hash"),)


class UserSession(Base):
    """A login session. The browser holds a random token; only its SHA-256 hash is
    stored, so a database leak does not hand out live sessions."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # False between the password step and the MFA step: such a session can only be
    # used to complete MFA.
    mfa_verified: Mapped[bool] = mapped_column(default=False)
    mfa_failures: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_user_sessions_user", "user_id"),)


class ClientAssignment(Base):
    """Which clients a Consultant may access. Admins do not need assignments."""

    __tablename__ = "client_assignments"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class AuditEvent(Base):
    """Append-only record of security-relevant actions. The database refuses UPDATE
    and DELETE on this table. No foreign keys on purpose: entries must outlive the
    users and clients they mention. Details never contain secrets."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    action: Mapped[str] = mapped_column(String(64))  # e.g. "auth.login"
    outcome: Mapped[str] = mapped_column(String(16))  # "success" / "failure" / "denied"
    actor_type: Mapped[str] = mapped_column(String(16))  # "user" / "cli" / "system" / "anonymous"
    actor_user_id: Mapped[uuid.UUID | None]
    actor_email: Mapped[str | None] = mapped_column(String(254))
    client_id: Mapped[uuid.UUID | None]
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)

    __table_args__ = (
        Index("ix_audit_events_time", "occurred_at"),
        Index("ix_audit_events_client", "client_id", "occurred_at"),
        Index("ix_audit_events_actor", "actor_user_id", "occurred_at"),
    )


# ------------------------------------------------------------------ review layer (M12)


class FindingReview(Base):
    """The CURRENT review decision for one finding of an assessment. Keyed by the
    finding's stable fingerprint, so a decision carries over to a rescan of the same
    assessment. The scan results themselves are never changed."""

    __tablename__ = "finding_reviews"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    assessment_id: Mapped[uuid.UUID]
    fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[ReviewStatus] = mapped_column(_enum(ReviewStatus, "review_status"))
    severity_override: Mapped[Severity | None] = mapped_column(_enum(Severity, "severity_override"))
    justification: Mapped[str | None] = mapped_column(String(2000))
    updated_by_user_id: Mapped[uuid.UUID | None]
    updated_by: Mapped[str] = mapped_column(String(254))  # e-mail, or "cli"
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "client_id"],
            ["assessments.id", "assessments.client_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("assessment_id", "fingerprint"),
        CheckConstraint(
            "(status NOT IN ('false_positive', 'accepted_risk') AND severity_override IS NULL)"
            " OR length(trim(coalesce(justification, ''))) >= 10",
            name="decision_justified",
        ),
    )


class FindingReviewEvent(Base):
    """History of review decisions (who changed what, when, why). Rows are never
    updated (database trigger); they are removed only with their assessment."""

    __tablename__ = "finding_review_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    assessment_id: Mapped[uuid.UUID]
    fingerprint: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    actor_user_id: Mapped[uuid.UUID | None]
    actor: Mapped[str] = mapped_column(String(254))
    status: Mapped[ReviewStatus] = mapped_column(_enum(ReviewStatus, "review_status"))
    severity_override: Mapped[Severity | None] = mapped_column(_enum(Severity, "severity_override"))
    justification: Mapped[str | None] = mapped_column(String(2000))
    previous_status: Mapped[ReviewStatus | None] = mapped_column(
        _enum(ReviewStatus, "previous_review_status")
    )
    previous_severity_override: Mapped[Severity | None] = mapped_column(
        _enum(Severity, "previous_severity_override")
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "client_id"],
            ["assessments.id", "assessments.client_id"],
            ondelete="CASCADE",
        ),
        Index("ix_finding_review_events_finding", "assessment_id", "fingerprint", "occurred_at"),
    )


class AssessmentFinalization(Base):
    """A finalized assessment: the reviewed report dataset, frozen, with its SHA-256.
    Every output of a finalized assessment is rendered from this snapshot. Rows are
    never updated; reopening an assessment keeps them as history."""

    __tablename__ = "assessment_finalizations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    assessment_id: Mapped[uuid.UUID]
    scan_run_id: Mapped[uuid.UUID]
    finalized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    finalized_by_user_id: Mapped[uuid.UUID | None]
    finalized_by: Mapped[str] = mapped_column(String(254))
    report: Mapped[dict[str, Any]] = mapped_column(JsonType)
    report_sha256: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "client_id"],
            ["assessments.id", "assessments.client_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["scan_run_id", "client_id"],
            ["scan_runs.id", "scan_runs.client_id"],
            ondelete="CASCADE",
        ),
        Index("ix_assessment_finalizations_assessment", "assessment_id", "finalized_at"),
        CheckConstraint("length(report_sha256) = 64", name="final_report_hash_length"),
    )


class FindingRecord(Base):
    """One finding from one scan run. A queryable copy of what is inside
    ScanRun.result, so dashboards can filter and count without parsing JSON."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID]
    scan_run_id: Mapped[uuid.UUID]
    fingerprint: Mapped[str] = mapped_column(String(64))  # stable across scans
    rule_id: Mapped[str] = mapped_column(String(32))
    rule_version: Mapped[int]
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    category: Mapped[Category] = mapped_column(_enum(Category, "category"))
    provider: Mapped[Provider] = mapped_column(_enum(Provider, "provider"))
    account_id: Mapped[str] = mapped_column(String(64))
    region: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(2048))
    resource_name: Mapped[str | None] = mapped_column(String(512))
    title: Mapped[str] = mapped_column(String(300))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data: Mapped[dict[str, Any]] = mapped_column(JsonType)  # the full Finding

    __table_args__ = (
        ForeignKeyConstraint(
            ["scan_run_id", "client_id"],
            ["scan_runs.id", "scan_runs.client_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("scan_run_id", "fingerprint"),
        Index("ix_findings_client_severity", "client_id", "severity"),
    )
