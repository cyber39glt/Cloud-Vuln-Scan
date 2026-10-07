"""The background worker: runs queued scans, one at a time (ADR 0003, ADR 0019).

    python -m app.worker

Loop: fail interrupted jobs → claim the oldest queued job → run the SAME scan
sequence as the CLI (app.scanning) → save the result and mark the job done. A scan
takes minutes, so it never runs inside a web request.

Safety properties:
- The job's cloud connection is read from the database and must belong to the same
  client as the job (composite foreign keys make anything else impossible).
- Failures are stored as plain-language messages; raw exception text is not stored.
- A read-only guard violation fails the job and is logged as an error: it would mean
  a platform bug, never something to retry.
- SIGTERM/SIGINT (e.g. `docker compose stop`) lets the current scan finish first.
"""

import logging
import signal
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.auth import audit
from app.core.config import Settings, get_settings
from app.core.database import get_sessionmaker
from app.core.logging import configure_logging
from app.domain.enums import Provider, ScanStage
from app.domain.findings import AssessmentResult
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.session import AwsConnection
from app.providers.azure.errors import describe_azure_error
from app.providers.azure.session import AzureConnection
from app.providers.common import ReadOnlyViolation
from app.scanning import WrongAccountError, scan_aws, scan_azure
from app.storage import jobs
from app.storage import repository as repo
from app.storage.models import Assessment, CloudConnection, ScanJob

# A fixed name: under "python -m app.worker" __name__ would be "__main__".
logger = logging.getLogger("app.worker")

# Touched on every loop; the container health check reads its age.
ALIVE_FILE = Path("/tmp/worker-alive")  # noqa: S108  liveness marker, holds no data


@dataclass(frozen=True)
class Scanners:
    """The scan functions, replaceable in tests (simulated clouds)."""

    aws: Callable[..., AssessmentResult] = scan_aws
    azure: Callable[..., AssessmentResult] = scan_azure


@dataclass(frozen=True)
class _Target:
    provider: Provider
    connection: AwsConnection | AzureConnection
    regions: list[str] | None


def _target(session: Session, job: ScanJob, settings: Settings) -> _Target:
    connection = session.scalar(
        select(CloudConnection)
        .join(Assessment, Assessment.connection_id == CloudConnection.id)
        .where(Assessment.id == job.assessment_id, Assessment.client_id == job.client_id)
    )
    if connection is None:  # cannot happen with the foreign keys; checked anyway
        raise repo.NotFoundError("connection for this job not found")
    if connection.provider == Provider.AWS:
        return _Target(
            Provider.AWS,
            AwsConnection(
                connection.account_id,
                connection.external_id or "",
                settings.aws_assessment_role_name,
            ),
            job.regions,
        )
    return _Target(
        Provider.AZURE,
        AzureConnection(connection.tenant_id or "", connection.account_id),
        job.regions,
    )


def _describe_failure(provider: Provider | None, error: Exception) -> tuple[str, str]:
    """(code, plain-language message) for the job record."""
    if isinstance(error, WrongAccountError):
        return "WrongAccount", f"Stopped before collecting anything: {error}."
    if isinstance(error, ReadOnlyViolation):
        return (
            "ReadOnlyViolation",
            "A platform safeguard blocked an operation that is not a read, and the scan "
            "was stopped. Nothing was changed in the client environment. This indicates "
            "a platform bug: please report it.",
        )
    if provider is None:
        return type(error).__name__, "The scan could not be prepared."
    describe = describe_aws_error if provider == Provider.AWS else describe_azure_error
    problem = describe(error)
    tip = "Run the connection validation for this account to diagnose."
    return problem.code, f"{problem.message} {problem.hint} {tip}".replace("  ", " ").strip()


class _Heartbeat:
    """Keeps a running job's heartbeat fresh while a long collection step runs, from
    a separate thread with its own database session."""

    def __init__(self, factory: sessionmaker[Session], job_id: uuid.UUID, every: float) -> None:
        self._factory, self._job_id, self._every = factory, job_id, every
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="scan-heartbeat", daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(self._every):
            try:
                with self._factory.begin() as session:
                    jobs.record_progress(session, self._job_id)
            except Exception as exc:  # a missed heartbeat must not kill the scan
                logger.warning("heartbeat failed", extra={"error_type": type(exc).__name__})

    def __enter__(self) -> "_Heartbeat":
        self._thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self._stop.set()
        self._thread.join()


def run_job(
    job_id: uuid.UUID,
    settings: Settings,
    factory: sessionmaker[Session],
    scanners: Scanners = Scanners(),  # noqa: B008  immutable default
) -> None:
    """Run one claimed (status=running) job to completion or failure."""
    provider: Provider | None = None
    log = {"scan_job_id": str(job_id)}
    try:
        with factory.begin() as session:
            job = session.get(ScanJob, job_id)
            if job is None:
                raise repo.NotFoundError("scan job not found")
            client_id, assessment_id = job.client_id, job.assessment_id
            target = _target(session, job, settings)
        provider = target.provider
        log |= {"client_id": str(client_id), "provider": provider.value}
        logger.info("scan started", extra=log)

        def progress(stage: ScanStage) -> None:
            try:
                with factory.begin() as session:
                    jobs.record_progress(session, job_id, stage)
            except Exception as exc:  # progress display must never break a scan
                logger.warning("progress update failed", extra={"error_type": type(exc).__name__})

        scan = scanners.aws if provider == Provider.AWS else scanners.azure
        with _Heartbeat(factory, job_id, settings.worker_heartbeat_seconds):
            result = scan(target.connection, settings, regions=target.regions, progress=progress)

        progress(ScanStage.SAVING)
        with factory.begin() as session:
            # The result and the job's completion are saved in ONE transaction: either
            # both are stored or neither is.
            scan_run = repo.save_scan_result(session, client_id, assessment_id, result)
            jobs.complete_job(session, session.get(ScanJob, job_id), scan_run.id)
            audit.record(
                session,
                "scan.completed",
                audit.SYSTEM,
                client_id=client_id,
                target_type="scan_run",
                target_id=scan_run.id,
                findings=len(result.findings),
            )
        logger.info(
            "scan succeeded",
            extra=log | {"scan_run_id": str(scan_run.id), "findings": len(result.findings)},
        )
    except Exception as exc:
        code, message = _describe_failure(provider, exc)
        level = logging.ERROR if isinstance(exc, ReadOnlyViolation) else logging.WARNING
        logger.log(level, "scan failed", extra=log | {"error_code": code})
        with factory.begin() as session:
            jobs.fail_job(session, job_id, code, message)
            job = session.get(ScanJob, job_id)
            audit.record(
                session,
                "scan.failed",
                audit.SYSTEM,
                outcome="failure",
                client_id=job.client_id if job else None,
                target_type="scan_job",
                target_id=job_id,
                error_code=code,
            )


def work_once(
    settings: Settings,
    factory: sessionmaker[Session],
    scanners: Scanners = Scanners(),  # noqa: B008  immutable default
) -> bool:
    """Fail interrupted jobs, then run the next queued job if any. True if one ran."""
    with factory.begin() as session:
        jobs.fail_stale_jobs(session, timedelta(seconds=settings.worker_stale_after_seconds))
    with factory.begin() as session:
        job = jobs.claim_next_job(session)
        job_id = job.id if job else None
    if job_id is None:
        return False
    run_job(job_id, settings, factory, scanners)
    return True


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    factory = get_sessionmaker()
    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        logger.info("worker stopping after the current scan", extra={"signal": signum})
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    logger.info("worker started", extra={"poll_seconds": settings.worker_poll_seconds})

    while not stop.is_set():
        ALIVE_FILE.touch()
        try:
            ran = work_once(settings, factory)
        except Exception as exc:  # e.g. database briefly unavailable: wait and retry
            logger.warning("worker loop error", extra={"error_type": type(exc).__name__})
            ran = False
        if not ran:
            stop.wait(settings.worker_poll_seconds)
    logger.info("worker stopped")


if __name__ == "__main__":
    main()
