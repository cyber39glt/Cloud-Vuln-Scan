"""The dashboard home screen: every assessment the user may see, with the severity
counts of its latest scan and any scan in progress. One request, client-scoped."""

import uuid
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.auth import service
from app.domain.enums import Provider, ScanStage, Severity
from app.storage.models import (
    ACTIVE_JOB_STATUSES,
    Assessment,
    AssessmentStatus,
    Client,
    CloudConnection,
    FindingRecord,
    FindingReview,
    JobStatus,
    ReviewStatus,
    ScanJob,
    ScanRun,
)

router = APIRouter(prefix="/api/v1", tags=["overview"])

EXCLUDED_FROM_TOTALS = (ReviewStatus.FALSE_POSITIVE, ReviewStatus.ACCEPTED_RISK)


class LatestScan(BaseModel):
    id: uuid.UUID
    completed_at: datetime
    findings: int
    by_severity: dict[Severity, int]


class ActiveJob(BaseModel):
    id: uuid.UUID
    status: JobStatus
    stage: ScanStage


class OverviewItem(BaseModel):
    client_id: uuid.UUID
    client_name: str
    assessment_id: uuid.UUID
    assessment_name: str
    assessment_status: AssessmentStatus
    provider: Provider
    account_id: str
    latest_scan: LatestScan | None
    active_job: ActiveJob | None


class Overview(BaseModel):
    clients: int
    items: list[OverviewItem]


@router.get("/overview")
def overview(db: DbSession, user: CurrentUser) -> Overview:
    clients = select(Client.id)
    if not user.is_admin:
        clients = clients.where(Client.id.in_(service.assigned_client_ids(db, user.id)))
    client_ids = set(db.scalars(clients))

    rows = db.execute(
        select(Assessment, Client.name, CloudConnection.provider, CloudConnection.account_id)
        .join(Client, Client.id == Assessment.client_id)
        .join(CloudConnection, CloudConnection.id == Assessment.connection_id)
        .where(Assessment.client_id.in_(client_ids))
        .order_by(Client.name, Assessment.created_at.desc())
    ).all()
    assessment_ids = [a.id for a, *_ in rows]

    # Latest completed scan per assessment (PostgreSQL DISTINCT ON).
    latest = {
        scan.assessment_id: scan
        for scan in db.scalars(
            select(ScanRun)
            .where(ScanRun.assessment_id.in_(assessment_ids))
            .order_by(ScanRun.assessment_id, ScanRun.completed_at.desc())
            .distinct(ScanRun.assessment_id)
        )
    }
    # Severity counts as the report shows them: review decisions applied (false
    # positives and accepted risks left out, adjusted severities used).
    decisions = {
        (r.assessment_id, r.fingerprint): r
        for r in db.scalars(
            select(FindingReview).where(FindingReview.assessment_id.in_(assessment_ids))
        )
    }
    scan_assessment = {scan.id: scan.assessment_id for scan in latest.values()}
    counts: dict[uuid.UUID, dict[Severity, int]] = {}
    for scan_id, fingerprint, severity in db.execute(
        select(FindingRecord.scan_run_id, FindingRecord.fingerprint, FindingRecord.severity).where(
            FindingRecord.scan_run_id.in_(list(scan_assessment))
        )
    ):
        review = decisions.get((scan_assessment[scan_id], fingerprint))
        if review is not None and review.status in EXCLUDED_FROM_TOTALS:
            continue
        effective = (review.severity_override if review else None) or severity
        bucket = counts.setdefault(scan_id, {})
        bucket[effective] = bucket.get(effective, 0) + 1
    active = {
        job.assessment_id: job
        for job in db.scalars(
            select(ScanJob).where(
                ScanJob.assessment_id.in_(assessment_ids),
                ScanJob.status.in_(ACTIVE_JOB_STATUSES),
            )
        )
    }

    items = []
    for assessment, client_name, provider, account_id in rows:
        scan = latest.get(assessment.id)
        job = active.get(assessment.id)
        by_severity = {s: counts.get(scan.id, {}).get(s, 0) for s in Severity} if scan else {}
        items.append(
            OverviewItem(
                client_id=assessment.client_id,
                client_name=client_name,
                assessment_id=assessment.id,
                assessment_name=assessment.name,
                assessment_status=assessment.status,
                provider=provider,
                account_id=account_id,
                latest_scan=LatestScan(
                    id=scan.id,
                    completed_at=scan.completed_at,
                    findings=sum(by_severity.values()),
                    by_severity=by_severity,
                )
                if scan
                else None,
                active_job=ActiveJob(id=job.id, status=job.status, stage=job.stage)
                if job
                else None,
            )
        )
    return Overview(clients=len(client_ids), items=items)
