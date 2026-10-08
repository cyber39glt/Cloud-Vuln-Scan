"""AWS IAM, S3 and RDS collection against simulated AWS (moto)."""

import json
from datetime import UTC, datetime

import boto3
import pytest
from botocore.client import BaseClient

from app.domain.enums import CheckStatus
from app.providers.aws.collect_iam import (
    ADMIN_POLICY,
    IAM_ACCOUNT,
    IAM_USER,
    PASSWORD_POLICY,
    collect_iam,
)
from app.providers.aws.collect_rds import RDS_INSTANCE, collect_rds
from app.providers.aws.collect_s3 import S3_ACCOUNT, S3_BUCKET, collect_s3
from app.providers.aws.guard import ReadOnlyViolation
from app.providers.aws.session import AwsConnection, assume_assessment_role
from app.scanning import scan_aws

ACCOUNT = "123456789012"
NOW = datetime(2026, 1, 15, tzinfo=UTC)
CONNECTION = AwsConnection(ACCOUNT, "subtletech-test-external-id", "SubtleTechSecurityAssessment")


def no_sleep(_seconds: float) -> None:
    pass


@pytest.fixture
def assessed_session(aws, settings):
    return assume_assessment_role(CONNECTION, settings)


def _one(resources, resource_type):
    [resource] = [r for r in resources if r.resource_type == resource_type]
    return resource


# ------------------------------------------------------------------ IAM


def test_iam_collects_root_password_policy_and_users(assessed_session):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(MinimumPasswordLength=8)
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Not-a-real-pw-123")  # gitleaks:allow
    iam.create_access_key(UserName="alice")
    iam.create_user(UserName="ci-bot")

    resources, gaps = collect_iam(assessed_session, ACCOUNT, NOW, sleep=no_sleep)

    root = _one(resources, IAM_ACCOUNT)
    assert root.properties == {"root_mfa_enabled": False, "root_access_keys_present": False}
    assert _one(resources, PASSWORD_POLICY).properties["minimum_length"] == 8
    users = {r.name: r.properties for r in resources if r.resource_type == IAM_USER}
    assert users["alice"]["password_enabled"] is True
    assert users["alice"]["mfa_active"] is False
    [key] = users["alice"]["access_keys"]
    assert set(key) == {"slot", "active", "last_rotated", "last_used"}  # no key IDs kept
    assert users["ci-bot"] == {"password_enabled": False, "mfa_active": False, "access_keys": []}
    assert gaps == []


def test_missing_password_policy_is_an_answer_not_a_gap(assessed_session):
    resources, _gaps = collect_iam(assessed_session, ACCOUNT, NOW, sleep=no_sleep)
    assert _one(resources, PASSWORD_POLICY).properties == {"exists": False}


@pytest.fixture
def managed_policies(monkeypatch):
    """moto only loads AWS-managed policies when asked, before it starts."""
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")


def test_administrator_access_attachments(managed_policies, assessed_session):
    iam = boto3.client("iam", region_name="us-east-1")
    admin = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.create_user(UserName="bob")
    iam.attach_user_policy(UserName="bob", PolicyArn=admin)
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=admin)

    resources, gaps = collect_iam(assessed_session, ACCOUNT, NOW, sleep=no_sleep)

    assert gaps == []
    policy = _one(resources, ADMIN_POLICY)
    assert (policy.properties["users"], policy.properties["groups"]) == (["bob"], ["admins"])


def test_credential_report_that_never_completes_is_a_gap(assessed_session):
    def always_started(model, **_):
        if model.name == "GenerateCredentialReport":
            return type("Http", (), {"status_code": 200})(), {"State": "STARTED"}
        return None

    assessed_session.events.register("before-call.iam", always_started)
    resources, gaps = collect_iam(assessed_session, ACCOUNT, NOW, sleep=no_sleep)

    assert not [r for r in resources if r.resource_type == IAM_USER]
    assert IAM_USER in [g.resource_type for g in gaps]


# ------------------------------------------------------------------ S3


def _bucket(name: str, region: str = "us-east-1") -> None:
    s3 = boto3.client("s3", region_name=region)
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})


def _public_read_policy(name: str) -> None:
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{name}/*",
    }
    boto3.client("s3", region_name="us-east-1").put_bucket_policy(
        Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    )


def test_s3_collects_account_settings_and_bucket_exposure(assessed_session):
    _bucket("cvs-public-policy")
    _public_read_policy("cvs-public-policy")
    _bucket("cvs-public-acl", "eu-west-2")
    boto3.client("s3", region_name="eu-west-2").put_bucket_acl(
        Bucket="cvs-public-acl", ACL="public-read"
    )
    _bucket("cvs-private")

    resources, gaps = collect_s3(assessed_session, ACCOUNT, None, NOW)

    assert gaps == []
    account = _one(resources, S3_ACCOUNT)
    assert not any(account.properties.values())  # no account-level block configured
    buckets = {r.name: r for r in resources if r.resource_type == S3_BUCKET}
    assert buckets["cvs-public-policy"].properties["policy_public"] is True
    assert buckets["cvs-public-acl"].properties["acl_public"] is True
    assert buckets["cvs-public-acl"].region == "eu-west-2"
    assert buckets["cvs-private"].properties["policy_public"] is False
    assert buckets["cvs-private"].properties["acl_public"] is False


def test_s3_region_scope_keeps_only_buckets_in_scope(assessed_session):
    _bucket("cvs-london", "eu-west-2")
    _bucket("cvs-virginia")
    resources, _ = collect_s3(assessed_session, ACCOUNT, ["eu-west-2"], NOW)
    assert [r.name for r in resources if r.resource_type == S3_BUCKET] == ["cvs-london"]


def test_unknown_policy_status_is_a_gap_not_a_guess(assessed_session, monkeypatch):
    """If AWS does not say whether a policy is public, we do not guess 'private'."""
    _bucket("cvs-unknown")
    simulated = BaseClient._make_api_call

    def without_is_public(self, operation_name, api_params):
        response = simulated(self, operation_name, api_params)
        if operation_name == "GetBucketPolicyStatus":
            response = {**response, "PolicyStatus": {}}
        return response

    monkeypatch.setattr(BaseClient, "_make_api_call", without_is_public)
    resources, gaps = collect_s3(assessed_session, ACCOUNT, None, NOW)

    assert not [r for r in resources if r.resource_type == S3_BUCKET]
    [gap] = gaps
    assert gap.resource_type == S3_BUCKET and "cvs-unknown" in gap.reason


# ------------------------------------------------------------------ RDS


def _database(identifier: str, public: bool, region: str = "us-east-1") -> None:
    boto3.client("rds", region_name=region).create_db_instance(
        DBInstanceIdentifier=identifier,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin_user",
        MasterUserPassword="Not-a-real-pw-123",  # gitleaks:allow
        AllocatedStorage=20,
        PubliclyAccessible=public,
    )


def test_rds_collects_public_flag_per_region(assessed_session):
    _database("public-db", True)
    _database("private-db", False, "eu-west-2")

    resources, gaps = collect_rds(assessed_session, ACCOUNT, ["us-east-1", "eu-west-2"], NOW)

    assert gaps == []
    found = {(r.name, r.region, r.properties["publicly_accessible"]) for r in resources}
    assert found == {("public-db", "us-east-1", True), ("private-db", "eu-west-2", False)}
    assert all(r.resource_type == RDS_INSTANCE for r in resources)
    assert set(resources[0].properties) == {"engine", "publicly_accessible"}


# ------------------------------------------------------------------ guard + end to end


def test_new_collectors_never_swallow_guard_violations(assessed_session, monkeypatch):
    from app.providers.aws import collect_iam as module

    def broken(*_args, **_kwargs):
        raise ReadOnlyViolation("Blocked by read-only guard: iam:DeleteUser is not allowed.")

    monkeypatch.setattr(module, "_account_summary", broken)
    with pytest.raises(ReadOnlyViolation):
        collect_iam(assessed_session, ACCOUNT, NOW, sleep=no_sleep)


def test_full_scan_reports_account_level_weaknesses(aws, settings, monkeypatch):
    monkeypatch.setattr("app.providers.aws.collect_iam.time.sleep", no_sleep)
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Not-a-real-pw-123")  # gitleaks:allow
    _bucket("cvs-public-policy")
    _public_read_policy("cvs-public-policy")
    _database("public-db", True)

    result = scan_aws(CONNECTION, settings, regions=["us-east-1"])

    found = {(f.rule_id, f.resource_name) for f in result.findings}
    assert {
        ("AWS-IAM-001", None),  # root without MFA
        ("AWS-IAM-003", "alice"),
        ("AWS-IAM-005", None),  # no password policy
        ("AWS-STO-001", None),
        ("AWS-STO-002", "cvs-public-policy"),
        ("AWS-EXP-001", "public-db"),
    } <= found
    statuses = {r.rule_id: r.status for r in result.results if r.rule_id == "AWS-IAM-002"}
    assert statuses == {"AWS-IAM-002": CheckStatus.PASS}
