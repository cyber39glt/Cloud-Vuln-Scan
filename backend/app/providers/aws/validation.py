"""Connection validation: before any scan, prove the connection works AND is safe.

Checks, in order (later checks are skipped if an earlier essential one fails):
1. The platform has an AWS identity.
2. The client's role can be assumed (trust policy + ExternalId are correct).
3. We landed in the expected account (protects against assessing the wrong client).
4. Each read permission the enabled rules need actually works.
5. The read-only guard is active (a harmless write attempt must be blocked locally).
"""

import logging
from collections.abc import Callable
from typing import Any

from botocore.exceptions import ClientError

from app.core.config import Settings
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.guard import ReadOnlyViolation, assessment_permissions
from app.providers.aws.session import (
    CLIENT_CONFIG,
    AwsConnection,
    assume_assessment_role,
    platform_session,
)
from app.providers.common import ValidationReport

logger = logging.getLogger(__name__)

Probe = Callable[[Any, str], object]  # (session, account_id)

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _absent_is_fine(call: Callable[[], object], *codes: str) -> object:
    """Some reads answer "not configured" with an error code; for a permission
    probe that still proves the permission works."""
    try:
        return call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in codes:
            return None
        raise


def _client(session: Any, service: str) -> Any:
    return session.client(service, config=CLIENT_CONFIG)


# One cheap, read-only call per permission. None = cannot be probed without
# knowing a specific resource (or without side effects); verified during collection.
PERMISSION_PROBES: dict[str, Probe | None] = {
    "ec2:DescribeRegions": lambda s, _: _client(s, "ec2").describe_regions(),
    "ec2:DescribeSecurityGroups": lambda s, _: _client(s, "ec2").describe_security_groups(
        MaxResults=5
    ),
    "cloudtrail:DescribeTrails": lambda s, _: _client(s, "cloudtrail").describe_trails(),
    "cloudtrail:GetTrailStatus": None,
    "iam:GetAccountSummary": lambda s, _: _client(s, "iam").get_account_summary(),
    "iam:GetAccountPasswordPolicy": lambda s, _: _absent_is_fine(
        _client(s, "iam").get_account_password_policy, "NoSuchEntity"
    ),
    "iam:ListEntitiesForPolicy": lambda s, _: _client(s, "iam").list_entities_for_policy(
        PolicyArn=ADMIN_POLICY_ARN, MaxItems=1
    ),
    "iam:GenerateCredentialReport": None,  # probing would rebuild the report
    "iam:GetCredentialReport": None,
    "s3:ListAllMyBuckets": lambda s, _: _client(s, "s3").list_buckets(),
    "s3:GetAccountPublicAccessBlock": lambda s, account: _absent_is_fine(
        lambda: _client(s, "s3control").get_public_access_block(AccountId=account),
        "NoSuchPublicAccessBlockConfiguration",
    ),
    "s3:GetBucketLocation": None,
    "s3:GetBucketPolicyStatus": None,
    "s3:GetBucketAcl": None,
    "s3:GetBucketPublicAccessBlock": None,
    "rds:DescribeDBInstances": lambda s, _: _client(s, "rds").describe_db_instances(MaxRecords=20),
}


def _problem_text(error: Exception) -> str:
    problem = describe_aws_error(error)
    return f"{problem.message} {problem.hint}".strip()


def validate_connection(
    connection: AwsConnection, settings: Settings, platform: Any | None = None
) -> ValidationReport:
    report = ValidationReport(account_id=connection.account_id)
    platform = platform or platform_session(settings)

    # 1. Platform identity
    try:
        caller = platform.client("sts", config=CLIENT_CONFIG).get_caller_identity()
        report.add("Platform AWS identity", "ok", caller["Arn"])
    except Exception as exc:
        report.add("Platform AWS identity", "failed", _problem_text(exc))
        return _finish(report)

    # 2. Assume the client's role
    try:
        session = assume_assessment_role(connection, settings, platform=platform)
        report.add("Assume assessment role", "ok", connection.role_arn)
    except Exception as exc:
        report.add("Assume assessment role", "failed", _problem_text(exc))
        return _finish(report)

    # 3. Correct account
    try:
        actual = session.client("sts", config=CLIENT_CONFIG).get_caller_identity()["Account"]
        if actual == connection.account_id:
            report.add("Expected account", "ok", actual)
        else:
            report.add(
                "Expected account", "failed", f"Expected {connection.account_id}, got {actual}"
            )
            return _finish(report)
    except Exception as exc:
        report.add("Expected account", "failed", _problem_text(exc))
        return _finish(report)

    # 4. Read permissions needed by the enabled rules
    for permission in sorted(assessment_permissions() | {"ec2:DescribeRegions"}):
        probe = PERMISSION_PROBES.get(permission)
        if probe is None:
            report.add(f"Permission {permission}", "skipped", "Verified during collection.")
            continue
        try:
            probe(session, connection.account_id)
            report.add(f"Permission {permission}", "ok")
        except Exception as exc:
            report.add(f"Permission {permission}", "failed", _problem_text(exc))

    # 5. Read-only guard: this write must be stopped BEFORE reaching AWS.
    try:
        session.client("ec2", config=CLIENT_CONFIG).delete_security_group(
            GroupId="sg-00000000000000000"  # deliberately non-existent
        )
        report.add("Read-only guard", "failed", "A write operation was NOT blocked.")
    except ReadOnlyViolation:
        report.add("Read-only guard", "ok", "Write operations are blocked locally.")
    except Exception as exc:
        report.add("Read-only guard", "failed", f"Write reached AWS: {_problem_text(exc)}")

    return _finish(report)


def _finish(report: ValidationReport) -> ValidationReport:
    logger.info(
        "aws connection validated",
        extra={
            "account_id": report.account_id,
            "ok": report.ok,
            "failed_checks": [c.name for c in report.checks if c.status == "failed"],
        },
    )
    return report
