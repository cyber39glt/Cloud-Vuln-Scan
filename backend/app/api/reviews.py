"""Finding review and assessment finalization (ADR 0007, ADR 0023).

Anyone with access to the client (assigned Consultant or Admin) can review findings
and finalize an assessment. Reopening a finalized assessment is an Admin action with
a written reason. Every action is audit-logged; review decisions also keep their own
history, visible to everyone working on the client.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select

from app.api.deps import AdminUser, ClientScope, CurrentUser, DbSession, client_ip
from app.auth import audit
from app.core.config import get_settings
from app.domain.enums import Severity
from app.reporting import finalize as finalizing
from app.storage import repository as repo
from app.storage import reviews
from app.storage.models import (
    AssessmentFinalization,
    FindingReview,
    FindingReviewEvent,
    ReviewStatus,
)

router = APIRouter(
    prefix="/api/v1/clients/{client_id}/assessments/{assessment_id}", tags=["review"]
)

Ip = Annotated[str | None, Depends(client_ip)]
Fingerprint = Annotated[str, Path(pattern=r"^[0-9a-f]{16,64}$")]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=2000)]


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: ReviewStatus
    severity_override: Severity | None = None
    justification: str | None = Field(default=None, max_length=2000)


class ReviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    fingerprint: str
    status: ReviewStatus
    severity_override: Severity | None
    justification: str | None
    updated_by: str
    updated_at: datetime


class ReviewEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    occurred_at: datetime
    actor: str
    status: ReviewStatus
    severity_override: Severity | None
    justification: str | None
    previous_status: ReviewStatus | None
    previous_severity_override: Severity | None


class ScanChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: uuid.UUID | None = None


class ConfirmRemainingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: uuid.UUID


class ReopenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Reason


class FinalizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    scan_run_id: uuid.UUID
    finalized_at: datetime
    finalized_by: str
    report_sha256: str


def _review_out(review: FindingReview) -> ReviewOut:
    return ReviewOut.model_validate(review)


@router.get("/reviews")
def list_reviews(assessment_id: uuid.UUID, client: ClientScope, db: DbSession) -> list[ReviewOut]:
    repo.get_assessment(db, client.id, assessment_id)
    rows = db.scalars(
        select(FindingReview)
        .where(FindingReview.client_id == client.id, FindingReview.assessment_id == assessment_id)
        .order_by(FindingReview.updated_at.desc())
    )
    return [_review_out(r) for r in rows]


@router.put("/reviews/{fingerprint}")
def set_review(
    assessment_id: uuid.UUID,
    fingerprint: Fingerprint,
    body: ReviewIn,
    client: ClientScope,
    db: DbSession,
    user: CurrentUser,
    ip: Ip,
) -> ReviewOut:
    try:
        review, event = reviews.set_review(
            db,
            client.id,
            assessment_id,
            fingerprint,
            body.status,
            body.severity_override,
            body.justification,
            user.id,
            user.user.email,
        )
    except reviews.ReviewNotAllowed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except reviews.JustificationRequired as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    audit.record(
        db,
        "finding.reviewed",
        user.actor,
        client_id=client.id,
        target_type="finding",
        target_id=fingerprint,
        ip_address=ip,
        assessment_id=str(assessment_id),
        status=body.status.value,
        severity_override=body.severity_override.value if body.severity_override else None,
        previous_status=event.previous_status.value if event.previous_status else None,
    )
    return _review_out(review)


@router.get("/reviews/{fingerprint}/history")
def review_history(
    assessment_id: uuid.UUID, fingerprint: Fingerprint, client: ClientScope, db: DbSession
) -> list[ReviewEventOut]:
    repo.get_assessment(db, client.id, assessment_id)
    events: list[FindingReviewEvent] = reviews.review_history(
        db, client.id, assessment_id, fingerprint
    )
    return [ReviewEventOut.model_validate(e) for e in events]


@router.post("/reviews/confirm-remaining")
def confirm_remaining(
    assessment_id: uuid.UUID,
    body: ConfirmRemainingIn,
    client: ClientScope,
    db: DbSession,
    user: CurrentUser,
    ip: Ip,
) -> dict[str, int]:
    """Confirm every finding of the scan that has no decision yet."""
    try:
        count = finalizing.confirm_remaining(
            db, client.id, assessment_id, body.scan_id, user.id, user.user.email
        )
    except reviews.ReviewNotAllowed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(
        db,
        "finding.reviewed",
        user.actor,
        client_id=client.id,
        target_type="scan_run",
        target_id=body.scan_id,
        ip_address=ip,
        assessment_id=str(assessment_id),
        status=ReviewStatus.CONFIRMED.value,
        bulk_count=count,
    )
    return {"confirmed": count}


@router.post("/finalize")
def finalize(
    assessment_id: uuid.UUID,
    body: ScanChoice,
    client: ClientScope,
    db: DbSession,
    user: CurrentUser,
    ip: Ip,
) -> FinalizationOut:
    """Freeze the reviewed report of a scan (default: the latest) and lock the assessment."""
    try:
        finalization: AssessmentFinalization = finalizing.finalize(
            db,
            client.id,
            assessment_id,
            get_settings().consultancy_name,
            user.id,
            user.user.email,
            body.scan_id,
        )
    except finalizing.FinalizationNotAllowed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(
        db,
        "assessment.finalized",
        user.actor,
        client_id=client.id,
        target_type="assessment",
        target_id=assessment_id,
        ip_address=ip,
        scan_run_id=str(finalization.scan_run_id),
        report_sha256=finalization.report_sha256,
    )
    return FinalizationOut.model_validate(finalization)


@router.post("/reopen", status_code=status.HTTP_204_NO_CONTENT)
def reopen(
    assessment_id: uuid.UUID,
    body: ReopenIn,
    client: ClientScope,
    db: DbSession,
    admin: AdminUser,
    ip: Ip,
) -> None:
    """Unlock a finalized assessment (Admins only, with a reason). The finalized
    snapshot is kept as history."""
    try:
        finalizing.reopen(db, client.id, assessment_id)
    except finalizing.FinalizationNotAllowed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(
        db,
        "assessment.reopened",
        admin.actor,
        client_id=client.id,
        target_type="assessment",
        target_id=assessment_id,
        ip_address=ip,
        reason=body.reason,
    )


@router.get("/finalizations")
def finalizations(
    assessment_id: uuid.UUID, client: ClientScope, db: DbSession
) -> list[FinalizationOut]:
    repo.get_assessment(db, client.id, assessment_id)
    return [
        FinalizationOut.model_validate(f)
        for f in reviews.finalization_history(db, client.id, assessment_id)
    ]
