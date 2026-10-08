"""Finalizing and reopening an assessment (ADR 0007, ADR 0023).

Finalize = build the REVIEWED report for one scan, freeze it with its SHA-256, and
lock the assessment (no more reviews or scans). Every output of a finalized
assessment is then rendered from that snapshot, so what was delivered can always be
reproduced exactly. Reopen (admins) unlocks it again; the snapshot stays as history.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.reporting.report import ReportSource, build_report
from app.storage import repository as repo
from app.storage import reviews
from app.storage.models import (
    ACTIVE_JOB_STATUSES,
    AssessmentFinalization,
    AssessmentStatus,
    Client,
    ReviewStatus,
    ScanJob,
    ScanRun,
)


class FinalizationNotAllowed(ValueError):
    """The assessment cannot be finalized (or reopened) now. Safe to show."""


def _latest_scan(session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID) -> ScanRun:
    scan = session.scalar(
        select(ScanRun)
        .where(ScanRun.client_id == client_id, ScanRun.assessment_id == assessment_id)
        .order_by(ScanRun.completed_at.desc())
        .limit(1)
    )
    if scan is None:
        raise FinalizationNotAllowed("This assessment has no completed scan to finalize.")
    return scan


def unreviewed_fingerprints(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID, scan_id: uuid.UUID
) -> list[str]:
    """Findings of the scan that still have no decision (status open)."""
    result = repo.load_scan_result(session, client_id, scan_id)
    decided = {
        fp
        for fp, review in reviews.load_reviews(session, client_id, assessment_id).items()
        if review.status != ReviewStatus.OPEN.value
    }
    return [f.finding_id for f in result.findings if f.finding_id not in decided]


def finalize(
    session: Session,
    client_id: uuid.UUID,
    assessment_id: uuid.UUID,
    consultancy: str,
    actor_user_id: uuid.UUID | None,
    actor: str,
    scan_id: uuid.UUID | None = None,
) -> AssessmentFinalization:
    assessment = repo.get_assessment(session, client_id, assessment_id)
    if assessment.status == AssessmentStatus.FINALIZED:
        raise FinalizationNotAllowed("This assessment is already finalized.")
    if session.scalar(
        select(ScanJob.id).where(
            ScanJob.assessment_id == assessment_id, ScanJob.status.in_(ACTIVE_JOB_STATUSES)
        )
    ):
        raise FinalizationNotAllowed("A scan of this assessment is still queued or running.")

    if scan_id is None:
        scan = _latest_scan(session, client_id, assessment_id)
    else:
        scan = session.scalar(
            select(ScanRun).where(
                ScanRun.id == scan_id,
                ScanRun.client_id == client_id,
                ScanRun.assessment_id == assessment_id,
            )
        )
        if scan is None:
            raise repo.NotFoundError("scan not found")

    open_items = unreviewed_fingerprints(session, client_id, assessment_id, scan.id)
    if open_items:
        raise FinalizationNotAllowed(
            f"{len(open_items)} finding(s) have not been reviewed yet. Review them (or "
            "confirm all remaining) before finalizing."
        )

    result = repo.load_scan_result(session, client_id, scan.id)  # verifies the scan hash
    client = session.get(Client, client_id)
    now = datetime.now(UTC)
    report = build_report(
        result,
        ReportSource(
            consultancy=consultancy,
            client_name=client.name if client else "",
            assessment_id=assessment.id,
            assessment_name=assessment.name,
            assessment_status=AssessmentStatus.FINALIZED.value,
            scan_id=scan.id,
            scan_sha256=scan.result_sha256,
            report_status="final",
            finalized_at=now,
            finalized_by=actor,
        ),
        reviews=reviews.load_reviews(session, client_id, assessment_id),
        generated_at=now,
    )
    report_json = report.model_dump(mode="json")
    return reviews.store_finalization(
        session,
        assessment,
        scan.id,
        report_json,
        repo.result_hash(report_json),
        actor_user_id,
        actor,
        now,
    )


def reopen(session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID) -> None:
    assessment = repo.get_assessment(session, client_id, assessment_id)
    if assessment.status != AssessmentStatus.FINALIZED:
        raise FinalizationNotAllowed("Only a finalized assessment can be reopened.")
    assessment.status = AssessmentStatus.IN_REVIEW
    session.flush()


def confirm_remaining(
    session: Session,
    client_id: uuid.UUID,
    assessment_id: uuid.UUID,
    scan_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    actor: str,
) -> int:
    """Mark every finding of the scan that has no decision yet as confirmed."""
    if not session.scalar(
        select(ScanRun.id).where(
            ScanRun.id == scan_id,
            ScanRun.client_id == client_id,
            ScanRun.assessment_id == assessment_id,
        )
    ):
        raise repo.NotFoundError("scan not found")
    remaining = unreviewed_fingerprints(session, client_id, assessment_id, scan_id)
    for fingerprint in remaining:
        reviews.set_review(
            session,
            client_id,
            assessment_id,
            fingerprint,
            ReviewStatus.CONFIRMED,
            None,
            None,
            actor_user_id,
            actor,
        )
    return len(remaining)
