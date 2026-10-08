"""Assessments, scan requests (queued for the worker), scan progress and reports."""

import re
import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.deps import ClientScope, CurrentUser, DbSession, Principal, client_ip
from app.api.schemas import (
    AssessmentCreate,
    AssessmentDetail,
    AssessmentOut,
    ScanJobOut,
    ScanRequest,
    ScanRunOut,
)
from app.auth import audit
from app.core.config import get_settings
from app.reporting.exports import to_csv
from app.reporting.pdf import to_pdf
from app.reporting.report import AssessmentReport, report_for_scan
from app.storage import jobs
from app.storage import repository as repo
from app.storage.models import Client

router = APIRouter(prefix="/api/v1/clients/{client_id}", tags=["assessments"])

Ip = Annotated[str | None, Depends(client_ip)]


@router.get("/assessments")
def list_assessments(client: ClientScope, db: DbSession) -> list[AssessmentOut]:
    return [AssessmentOut.model_validate(a) for a in repo.list_assessments(db, client.id)]


@router.post("/assessments", status_code=status.HTTP_201_CREATED)
def create_assessment(
    body: AssessmentCreate, client: ClientScope, db: DbSession, user: CurrentUser, ip: Ip
) -> AssessmentOut:
    connection = repo.get_connection_by_id(db, client.id, body.connection_id)
    if repo.find_assessment_by_name(db, client.id, connection.id, body.name):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This connection already has an assessment with this name."
        )
    assessment = repo.create_assessment(db, client.id, connection.id, body.name)
    audit.record(
        db,
        "assessment.created",
        user.actor,
        client_id=client.id,
        target_type="assessment",
        target_id=assessment.id,
        ip_address=ip,
    )
    return AssessmentOut.model_validate(assessment)


@router.get("/assessments/{assessment_id}")
def get_assessment(
    assessment_id: uuid.UUID, client: ClientScope, db: DbSession
) -> AssessmentDetail:
    assessment = repo.get_assessment(db, client.id, assessment_id)
    runs = repo.list_scan_runs(db, client.id, assessment.id)
    counts = repo.finding_counts(db, client.id, [r.id for r in runs])
    return AssessmentDetail(
        **AssessmentOut.model_validate(assessment).model_dump(),
        scans=[
            ScanRunOut(
                id=r.id,
                provider=r.provider,
                account_id=r.account_id,
                regions=r.regions,
                started_at=r.started_at,
                completed_at=r.completed_at,
                findings=counts.get(r.id, 0),
            )
            for r in runs
        ],
    )


# ------------------------------------------------------------------ scans (via the worker)


@router.post("/assessments/{assessment_id}/scans", status_code=status.HTTP_202_ACCEPTED)
def request_scan(
    assessment_id: uuid.UUID,
    body: ScanRequest,
    client: ClientScope,
    db: DbSession,
    user: CurrentUser,
    ip: Ip,
    response: Response,
) -> ScanJobOut:
    """Queue a read-only scan of the assessment's cloud account. Returns at once
    (202 Accepted); follow progress at the URL in the Location header."""
    try:
        job = jobs.enqueue_scan(db, client.id, assessment_id, body.regions)
    except jobs.ScanNotAllowed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(
        db,
        "scan.requested",
        user.actor,
        client_id=client.id,
        target_type="scan_job",
        target_id=job.id,
        ip_address=ip,
        assessment_id=str(assessment_id),
        regions=body.regions,
    )
    response.headers["Location"] = f"/api/v1/clients/{client.id}/scan-jobs/{job.id}"
    return ScanJobOut.model_validate(job)


@router.get("/assessments/{assessment_id}/scan-jobs")
def list_scan_jobs(
    assessment_id: uuid.UUID, client: ClientScope, db: DbSession
) -> list[ScanJobOut]:
    repo.get_assessment(db, client.id, assessment_id)  # 404 if not this client's
    return [ScanJobOut.model_validate(j) for j in jobs.list_jobs(db, client.id, assessment_id)]


@router.get("/scan-jobs/{job_id}")
def get_scan_job(job_id: uuid.UUID, client: ClientScope, db: DbSession) -> ScanJobOut:
    return ScanJobOut.model_validate(jobs.get_job(db, client.id, job_id))


# ------------------------------------------------------------------ reports


@router.get("/scans/{scan_id}/report")
def get_report(
    scan_id: uuid.UUID, client: ClientScope, db: DbSession, user: CurrentUser, ip: Ip
) -> AssessmentReport:
    """The report dataset (same as the JSON export), integrity-checked on every read."""
    report = report_for_scan(db, client.id, scan_id, get_settings().consultancy_name)
    audit.record(
        db,
        "report.viewed",
        user.actor,
        client_id=client.id,
        target_type="scan_run",
        target_id=scan_id,
        ip_address=ip,
        format="json",
    )
    return report


def _export(
    scan_id: uuid.UUID,
    client: Client,
    db: Session,
    user: Principal,
    ip: str | None,
    extension: str,
    media_type: str,
    render: Callable[[AssessmentReport], bytes],
) -> Response:
    """A downloadable report file (CSV or PDF), audit-logged as an export."""
    report = report_for_scan(db, client.id, scan_id, get_settings().consultancy_name)
    audit.record(
        db,
        "report.exported",
        user.actor,
        client_id=client.id,
        target_type="scan_run",
        target_id=scan_id,
        ip_address=ip,
        format=extension,
    )
    # File names use safe characters only: client names are free text.
    slug = re.sub(r"[^A-Za-z0-9]+", "-", client.name).strip("-").lower()[:40] or "client"
    return Response(
        content=render(report),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{slug}_{str(scan_id)[:8]}.{extension}"'
        },
    )


@router.get("/scans/{scan_id}/report.csv", response_class=Response)
def get_report_csv(
    scan_id: uuid.UUID, client: ClientScope, db: DbSession, user: CurrentUser, ip: Ip
) -> Response:
    return _export(scan_id, client, db, user, ip, "csv", "text/csv; charset=utf-8", to_csv)


@router.get("/scans/{scan_id}/report.pdf", response_class=Response)
def get_report_pdf(
    scan_id: uuid.UUID, client: ClientScope, db: DbSession, user: CurrentUser, ip: Ip
) -> Response:
    """The client-facing PDF report, from the same dataset as every other output."""
    return _export(scan_id, client, db, user, ip, "pdf", "application/pdf", to_pdf)
