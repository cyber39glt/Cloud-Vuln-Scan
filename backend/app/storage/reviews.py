"""Review decisions, their history, and assessment finalization (ADR 0007, 0023).

Client-scoped like the rest of the repository. The stored scan results are never
touched: reviews are a separate layer, applied when a report is built.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.domain.enums import Severity
from app.domain.reviews import Review
from app.storage import repository as repo
from app.storage.models import (
    REVIEW_STATUSES_NEEDING_JUSTIFICATION,
    Assessment,
    AssessmentFinalization,
    AssessmentStatus,
    FindingRecord,
    FindingReview,
    FindingReviewEvent,
    ReviewStatus,
    ScanRun,
)
from app.storage.repository import NotFoundError

MIN_JUSTIFICATION = 10


class ReviewNotAllowed(ValueError):
    """The decision cannot be recorded now (e.g. finalized). Safe to show."""


class JustificationRequired(ValueError):
    """The decision needs a written reason. Safe to show."""


def _now() -> datetime:
    return datetime.now(UTC)


def load_reviews(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID
) -> dict[str, Review]:
    rows = session.scalars(
        select(FindingReview).where(
            FindingReview.client_id == client_id, FindingReview.assessment_id == assessment_id
        )
    )
    return {
        r.fingerprint: Review(
            status=r.status.value,
            severity_override=r.severity_override,
            justification=r.justification,
            reviewed_by=r.updated_by,
            reviewed_at=r.updated_at,
        )
        for r in rows
    }


def set_review(
    session: Session,
    client_id: uuid.UUID,
    assessment_id: uuid.UUID,
    fingerprint: str,
    status: ReviewStatus,
    severity_override: Severity | None,
    justification: str | None,
    actor_user_id: uuid.UUID | None,
    actor: str,
) -> tuple[FindingReview, FindingReviewEvent]:
    """Record a decision (replacing the current one) and append it to the history."""
    assessment = repo.get_assessment(session, client_id, assessment_id, for_update=True)
    if assessment.status == AssessmentStatus.FINALIZED:
        raise ReviewNotAllowed("This assessment is finalized. Reopen it to change reviews.")
    in_assessment = session.scalar(
        select(
            exists().where(
                FindingRecord.client_id == client_id,
                FindingRecord.fingerprint == fingerprint,
                FindingRecord.scan_run_id.in_(
                    select(ScanRun.id).where(
                        ScanRun.assessment_id == assessment_id, ScanRun.client_id == client_id
                    )
                ),
            )
        )
    )
    if not in_assessment:
        raise NotFoundError("finding not found")

    justification = (justification or "").strip() or None
    needs_reason = status in REVIEW_STATUSES_NEEDING_JUSTIFICATION or severity_override is not None
    if needs_reason and len(justification or "") < MIN_JUSTIFICATION:
        raise JustificationRequired(
            "Explain the decision (at least 10 characters): false positives, accepted "
            "risks and severity changes must be justified."
        )

    review = session.scalar(
        select(FindingReview).where(
            FindingReview.assessment_id == assessment_id, FindingReview.fingerprint == fingerprint
        )
    )
    previous_status = review.status if review else None
    previous_severity = review.severity_override if review else None
    now = _now()
    if review is None:
        review = FindingReview(
            client_id=client_id, assessment_id=assessment_id, fingerprint=fingerprint
        )
        session.add(review)
    review.status = status
    review.severity_override = severity_override
    review.justification = justification
    review.updated_by_user_id = actor_user_id
    review.updated_by = actor
    review.updated_at = now
    event = FindingReviewEvent(
        client_id=client_id,
        assessment_id=assessment_id,
        fingerprint=fingerprint,
        occurred_at=now,
        actor_user_id=actor_user_id,
        actor=actor,
        status=status,
        severity_override=severity_override,
        justification=justification,
        previous_status=previous_status,
        previous_severity_override=previous_severity,
    )
    session.add(event)
    session.flush()
    return review, event


def review_history(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID, fingerprint: str
) -> list[FindingReviewEvent]:
    return list(
        session.scalars(
            select(FindingReviewEvent)
            .where(
                FindingReviewEvent.client_id == client_id,
                FindingReviewEvent.assessment_id == assessment_id,
                FindingReviewEvent.fingerprint == fingerprint,
            )
            .order_by(FindingReviewEvent.occurred_at.desc())
        )
    )


# ------------------------------------------------------------------ finalization


def current_finalization(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID
) -> AssessmentFinalization | None:
    """The snapshot in force: the latest finalization, if the assessment is finalized."""
    assessment = session.scalar(
        select(Assessment).where(Assessment.id == assessment_id, Assessment.client_id == client_id)
    )
    if assessment is None or assessment.status != AssessmentStatus.FINALIZED:
        return None
    return session.scalar(
        select(AssessmentFinalization)
        .where(
            AssessmentFinalization.client_id == client_id,
            AssessmentFinalization.assessment_id == assessment_id,
        )
        .order_by(AssessmentFinalization.finalized_at.desc())
        .limit(1)
    )


def finalization_history(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID
) -> list[AssessmentFinalization]:
    return list(
        session.scalars(
            select(AssessmentFinalization)
            .where(
                AssessmentFinalization.client_id == client_id,
                AssessmentFinalization.assessment_id == assessment_id,
            )
            .order_by(AssessmentFinalization.finalized_at.desc())
        )
    )


def finalization_mac(
    finalization_id: uuid.UUID,
    client_id: uuid.UUID,
    assessment_id: uuid.UUID,
    scan_run_id: uuid.UUID,
    report_sha256: str,
) -> str:
    return repo.integrity_mac(
        "finalization", finalization_id, client_id, assessment_id, scan_run_id, report_sha256
    )


def store_finalization(
    session: Session,
    assessment: Assessment,
    scan_run_id: uuid.UUID,
    report_json: dict[str, Any],
    report_sha256: str,
    actor_user_id: uuid.UUID | None,
    actor: str,
    finalized_at: datetime,
) -> AssessmentFinalization:
    finalization_id = uuid.uuid4()
    finalization = AssessmentFinalization(
        id=finalization_id,
        client_id=assessment.client_id,
        assessment_id=assessment.id,
        scan_run_id=scan_run_id,
        finalized_at=finalized_at,
        finalized_by_user_id=actor_user_id,
        finalized_by=actor,
        report=report_json,
        report_sha256=report_sha256,
        report_mac=finalization_mac(
            finalization_id, assessment.client_id, assessment.id, scan_run_id, report_sha256
        ),
    )
    session.add(finalization)
    assessment.status = AssessmentStatus.FINALIZED
    session.flush()
    return finalization
