"""The background worker and the scan job queue, against the test database.

Cloud access is simulated: moto for AWS, and stand-in scan functions for failure
cases and Azure. The worker code path (claim → scan → save → complete) is real.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.domain.enums import ScanStage
from app.providers.common import ReadOnlyViolation
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory, sample_azure_inventory
from app.scanning import WrongAccountError
from app.storage import jobs
from app.storage import repository as repo
from app.storage.models import AuditEvent, Client, FindingRecord, JobStatus, ScanJob, ScanRun
from app.worker import Scanners, work_once

pytestmark = pytest.mark.integration

ACCOUNT = "123456789012"  # moto's default account
TENANT = "22222222-2222-2222-2222-222222222222"
SUB = "00000000-0000-0000-0000-000000000000"  # the sample Azure inventory's subscription


@pytest.fixture
def worker_settings() -> Settings:
    # A long heartbeat interval: the heartbeat thread must not share the test's
    # single database connection while a test runs.
    return Settings(_env_file=None, worker_heartbeat_seconds=300)


@pytest.fixture
def factory(db) -> sessionmaker[Session]:
    return sessionmaker(
        bind=db.connection(), join_transaction_mode="create_savepoint", expire_on_commit=False
    )


def _aws_job(db, regions=None, name="Acme Ltd") -> ScanJob:
    client = repo.create_client(db, name)
    connection = repo.get_or_create_aws_connection(db, client.id, ACCOUNT, "SubtleTech")
    assessment = repo.create_assessment(db, client.id, connection.id, "Q1")
    return jobs.enqueue_scan(db, client.id, assessment.id, regions)


def _refresh(db, job: ScanJob) -> ScanJob:
    db.expire_all()
    return db.get(ScanJob, job.id)


def failing(error: Exception):
    def scan(*_args, **_kwargs):
        raise error

    return scan


# ------------------------------------------------------------------ the happy path


def test_aws_scan_job_runs_and_saves_the_result(db, factory, worker_settings, aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group = ec2.create_security_group(GroupName="ssh-open", Description="x")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    job = _aws_job(db, regions=["us-east-1"])

    assert work_once(worker_settings, factory) is True

    job = _refresh(db, job)
    assert (job.status, job.stage, job.error_code) == (JobStatus.SUCCEEDED, ScanStage.DONE, None)
    assert job.started_at and job.finished_at and job.finished_at >= job.started_at
    scan = db.get(ScanRun, job.scan_run_id)
    assert scan.regions == ["us-east-1"] and scan.client_id == job.client_id
    rules = set(
        db.scalars(select(FindingRecord.rule_id).where(FindingRecord.scan_run_id == scan.id))
    )
    assert "NET-001" in rules
    assert work_once(worker_settings, factory) is False  # queue now empty
    [event] = db.scalars(select(AuditEvent).where(AuditEvent.action == "scan.completed"))
    assert (event.actor_type, event.client_id, event.target_id) == (
        "system",
        job.client_id,
        str(scan.id),
    )


def test_azure_job_uses_the_stored_tenant_and_subscription(db, factory, worker_settings):
    client = repo.create_client(db, "Globex")
    connection = repo.get_or_create_azure_connection(db, client.id, TENANT, SUB)
    assessment = repo.create_assessment(db, client.id, connection.id, "Azure Q1")
    job = jobs.enqueue_scan(db, client.id, assessment.id, ["uksouth"])
    seen = {}

    def fake_azure(connection, settings, regions, progress):
        seen.update(tenant=connection.tenant_id, sub=connection.subscription_id, regions=regions)
        return RuleEngine().run(sample_azure_inventory())

    work_once(worker_settings, factory, Scanners(azure=fake_azure))

    assert seen == {"tenant": TENANT, "sub": SUB, "regions": ["uksouth"]}
    assert _refresh(db, job).status == JobStatus.SUCCEEDED


def test_progress_is_visible_while_the_scan_runs(db, factory, worker_settings):
    job = _aws_job(db)
    observed = []

    def scan(connection, settings, regions, progress):
        for stage in (ScanStage.CONNECTING, ScanStage.COLLECTING, ScanStage.EVALUATING):
            progress(stage)
            observed.append(_refresh(db, job).stage)
        return RuleEngine().run(sample_aws_inventory())

    work_once(worker_settings, factory, Scanners(aws=scan))
    assert observed == [ScanStage.CONNECTING, ScanStage.COLLECTING, ScanStage.EVALUATING]


# ------------------------------------------------------------------ failures


@pytest.mark.parametrize(
    "error, code, fragment",
    [
        (
            WrongAccountError("expected account 123456789012, got 999988887777"),
            "WrongAccount",
            "Stopped before collecting anything",
        ),
        (
            ReadOnlyViolation("Blocked by read-only guard: ec2:DeleteVpc is not allowed."),
            "ReadOnlyViolation",
            "Nothing was changed in the client environment",
        ),
        (
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "secret detail"}}, "AssumeRole"
            ),
            "AccessDenied",
            "AWS denied the request.",
        ),
        (RuntimeError("password=hunter2 in a traceback"), "RuntimeError", "Unexpected error."),
    ],
)
def test_failures_are_stored_in_plain_language(db, factory, worker_settings, error, code, fragment):
    job = _aws_job(db)
    work_once(worker_settings, factory, Scanners(aws=failing(error)))

    job = _refresh(db, job)
    assert (job.status, job.error_code) == (JobStatus.FAILED, code)
    assert fragment in job.error_message
    assert "hunter2" not in job.error_message and "secret detail" not in job.error_message
    assert job.scan_run_id is None
    assert db.scalar(select(ScanRun).where(ScanRun.client_id == job.client_id)) is None
    failed = db.scalar(select(AuditEvent).where(AuditEvent.action == "scan.failed"))
    assert failed.details == {"error_code": code} and failed.outcome == "failure"


def test_guard_violation_is_logged_as_an_error(db, factory, worker_settings, caplog):
    _aws_job(db)
    with caplog.at_level(logging.WARNING, logger="app.worker"):
        work_once(worker_settings, factory, Scanners(aws=failing(ReadOnlyViolation("x"))))
    [record] = [r for r in caplog.records if r.getMessage() == "scan failed"]
    assert record.levelno == logging.ERROR


def test_a_failed_scan_can_be_requested_again(db, factory, worker_settings):
    job = _aws_job(db)
    with pytest.raises(jobs.ScanNotAllowed):
        jobs.enqueue_scan(db, job.client_id, job.assessment_id)
    work_once(worker_settings, factory, Scanners(aws=failing(RuntimeError())))
    db.expire_all()
    assert jobs.enqueue_scan(db, job.client_id, job.assessment_id).status == JobStatus.QUEUED


def test_interrupted_jobs_are_failed_not_left_running(db, factory, worker_settings):
    job = _aws_job(db)
    job.status, job.heartbeat_at = JobStatus.RUNNING, datetime.now(UTC) - timedelta(hours=1)
    db.flush()

    assert work_once(worker_settings, factory) is False

    job = _refresh(db, job)
    assert (job.status, job.error_code) == (JobStatus.FAILED, "Interrupted")


def test_jobs_run_oldest_first(db, factory, worker_settings):
    first, second = _aws_job(db, name="First"), _aws_job(db, name="Second")
    second.requested_at = first.requested_at - timedelta(minutes=1)
    db.flush()
    with factory.begin() as session:
        assert jobs.claim_next_job(session).id == second.id


# ------------------------------------------------------------------ concurrency (committed data)


def test_two_workers_never_claim_the_same_job(test_engine):
    """SKIP LOCKED: while one worker holds a job's row lock, another skips it."""
    with Session(test_engine) as setup:
        first = _aws_job(setup, name=f"A-{uuid.uuid4()}")
        second = _aws_job(setup, name=f"B-{uuid.uuid4()}")
        setup.commit()
        job_ids = {first.id, second.id}
        client_ids = [first.client_id, second.client_id]
    try:
        with Session(test_engine) as worker_a, Session(test_engine) as worker_b:
            claimed_a = jobs.claim_next_job(worker_a)  # row lock held: not committed yet
            claimed_b = jobs.claim_next_job(worker_b)
            claimed_none = jobs.claim_next_job(worker_b)
            assert {claimed_a.id, claimed_b.id} == job_ids
            assert claimed_none is None
            worker_a.rollback()
            worker_b.rollback()
    finally:
        with Session(test_engine) as cleanup:
            cleanup.execute(delete(Client).where(Client.id.in_(client_ids)))
            cleanup.commit()
