"""The scan job queue (ADR 0003, ADR 0019): a PostgreSQL table, no message broker.

    API:     enqueue_scan()          -> job "queued"
    Worker:  claim_next_job()        -> "running" (row lock: no two workers get it)
             record_progress()       -> stage + heartbeat
             complete_job() / fail_job()
             fail_stale_jobs()       -> "failed" if a worker died mid-scan

Like the rest of the repository, every lookup a user can trigger is client-scoped.
The worker-side functions work across clients by design: the worker serves them all.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.logging import redact_text
from app.domain.enums import ScanStage
from app.storage import repository as repo
from app.storage.models import (
    ACTIVE_JOB_STATUSES,
    AssessmentStatus,
    JobStatus,
    ScanJob,
)
from app.storage.repository import NotFoundError

logger = logging.getLogger(__name__)

MAX_ERROR_MESSAGE = 1000


class ScanNotAllowed(RuntimeError):
    """A scan cannot be started now (one is already active, or the assessment is final)."""


def _now() -> datetime:
    return datetime.now(UTC)


# ------------------------------------------------------------------ API side (client-scoped)


def enqueue_scan(
    session: Session,
    client_id: uuid.UUID,
    assessment_id: uuid.UUID,
    regions: list[str] | None = None,
) -> ScanJob:
    assessment = repo.get_assessment(session, client_id, assessment_id, for_update=True)
    if assessment.status == AssessmentStatus.FINALIZED:
        raise ScanNotAllowed("this assessment is finalized; start a new assessment to rescan")

    job = ScanJob(client_id=client_id, assessment_id=assessment_id, regions=regions)
    try:
        # A savepoint, so a refused insert does not spoil the caller's transaction.
        with session.begin_nested():
            session.add(job)
            session.flush()
    except IntegrityError as exc:
        # The partial unique index allows one queued/running job per assessment.
        raise ScanNotAllowed("a scan of this assessment is already queued or running") from exc
    logger.info(
        "scan queued",
        extra={"client_id": str(client_id), "scan_job_id": str(job.id)},
    )
    return job


def get_job(session: Session, client_id: uuid.UUID, job_id: uuid.UUID) -> ScanJob:
    job = session.scalar(
        select(ScanJob).where(ScanJob.id == job_id, ScanJob.client_id == client_id)
    )
    if job is None:
        raise NotFoundError("scan job not found")
    return job


def list_jobs(
    session: Session, client_id: uuid.UUID, assessment_id: uuid.UUID, limit: int = 20
) -> list[ScanJob]:
    return list(
        session.scalars(
            select(ScanJob)
            .where(ScanJob.client_id == client_id, ScanJob.assessment_id == assessment_id)
            .order_by(ScanJob.requested_at.desc())
            .limit(limit)
        )
    )


# ------------------------------------------------------------------ worker side


def claim_next_job(session: Session) -> ScanJob | None:
    """Take the oldest queued job and mark it running. SKIP LOCKED makes concurrent
    workers pass over a row another worker is claiming instead of waiting for it.
    The caller commits, which releases the row lock."""
    job = session.scalar(
        select(ScanJob)
        .where(ScanJob.status == JobStatus.QUEUED)
        .order_by(ScanJob.requested_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        return None
    now = _now()
    job.status = JobStatus.RUNNING
    job.stage = ScanStage.CONNECTING
    job.started_at = now
    job.heartbeat_at = now
    session.flush()
    return job


def record_progress(session: Session, job_id: uuid.UUID, stage: ScanStage | None = None) -> None:
    """Refresh the heartbeat (and the stage, if given) of a running job."""
    values: dict = {"heartbeat_at": _now()}
    if stage is not None:
        values["stage"] = stage
    session.execute(
        update(ScanJob)
        .where(ScanJob.id == job_id, ScanJob.status == JobStatus.RUNNING)
        .values(**values)
    )


def complete_job(session: Session, job: ScanJob, scan_run_id: uuid.UUID) -> None:
    job.status = JobStatus.SUCCEEDED
    job.stage = ScanStage.DONE
    job.scan_run_id = scan_run_id
    job.finished_at = _now()
    session.flush()


def fail_job(session: Session, job_id: uuid.UUID, code: str, message: str) -> None:
    """Record a failure. The message is shown to consultants, so it must already be
    plain language; it is redacted and truncated here as a last line of defence."""
    session.execute(
        update(ScanJob)
        .where(ScanJob.id == job_id, ScanJob.status.in_(ACTIVE_JOB_STATUSES))
        .values(
            status=JobStatus.FAILED,
            finished_at=_now(),
            error_code=code[:64],
            error_message=redact_text(message)[:MAX_ERROR_MESSAGE],
        )
    )


def fail_stale_jobs(session: Session, stale_after: timedelta) -> int:
    """Running jobs whose heartbeat stopped (worker crashed or was killed) are marked
    failed, so the assessment can be scanned again. They are not retried
    automatically: a consultant decides whether to start another scan."""
    result = session.execute(
        update(ScanJob)
        .where(
            ScanJob.status == JobStatus.RUNNING,
            ScanJob.heartbeat_at < _now() - stale_after,
        )
        .values(
            status=JobStatus.FAILED,
            finished_at=_now(),
            error_code="Interrupted",
            error_message="The scan stopped unexpectedly (the worker was restarted or "
            "crashed). Nothing was saved. Start the scan again.",
        )
    )
    if result.rowcount:
        logger.warning("stale scan jobs failed", extra={"count": result.rowcount})
    return result.rowcount
