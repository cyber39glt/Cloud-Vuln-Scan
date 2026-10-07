"""The dashboard home screen: every assessment the user may see, with the severity
counts of its latest scan and any scan in progress. One request, client-scoped."""

import uuid
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

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
    JobStatus,
    ScanJob,
    ScanRun,
)

router = APIRouter(prefix="/api/v1", tags=["overview"])


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
    counts: dict[uuid.UUID, dict[Severity, int]] = {}
    for scan_id, severity, count in db.execute(
        select(FindingRecord.scan_run_id, FindingRecord.severity, func.count())
        .where(FindingRecord.scan_run_id.in_([s.id for s in latest.values()]))
        .group_by(FindingRecord.scan_run_id, FindingRecord.severity)
    ):
        counts.setdefault(scan_id, {})[severity] = count
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
