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

from app.core.config import Settings
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.guard import ReadOnlyViolation, assessment_operations
from app.providers.aws.session import (
    CLIENT_CONFIG,
    AwsConnection,
    assume_assessment_role,
    platform_session,
)
from app.providers.common import ValidationReport

logger = logging.getLogger(__name__)

Probe = Callable[[Any], object]

# One cheap, read-only call per permission. None = cannot be probed without
# knowing a specific resource; it is verified during collection instead.
PERMISSION_PROBES: dict[str, Probe | None] = {
    "ec2:DescribeRegions": lambda s: s.client("ec2", config=CLIENT_CONFIG).describe_regions(),
    "ec2:DescribeSecurityGroups": lambda s: s.client(
        "ec2", config=CLIENT_CONFIG
    ).describe_security_groups(MaxResults=5),
    "cloudtrail:DescribeTrails": lambda s: s.client(
        "cloudtrail", config=CLIENT_CONFIG
    ).describe_trails(),
    "cloudtrail:GetTrailStatus": None,
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
    for operation in sorted(assessment_operations() - {"sts:GetCallerIdentity"}):
        probe = PERMISSION_PROBES.get(operation)
        if probe is None:
            report.add(f"Permission {operation}", "skipped", "Verified during collection.")
            continue
        try:
            probe(session)
            report.add(f"Permission {operation}", "ok")
        except Exception as exc:
            report.add(f"Permission {operation}", "failed", _problem_text(exc))

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
