"""Application-side read-only guard for AWS (layer 2 of ADR 0002).

boto3 is built on botocore, which fires events while preparing every API request.
We hook the earliest one ("before-parameter-build", even before parameters are
checked) and raise unless the operation is on an explicit allowlist, so a blocked
request is never built, let alone sent.

An ALLOWlist (not a blocklist) means anything unknown is refused: a new AWS write
operation released tomorrow is blocked without any change here.
"""

from collections.abc import Iterable
from typing import Any

import boto3

from app.domain.enums import Provider
from app.providers.common import ReadOnlyViolation
from app.rules.registry import ALL_RULES

__all__ = [
    "ReadOnlyViolation",
    "guarded_session",
    "install_guard",
    "assessment_operations",
    "assessment_permissions",
]

# Read operations are named Describe*, List* or Get* in AWS APIs.
READ_PREFIXES = ("Describe", "List", "Get")

# The ONLY exception to the prefix rule, each justified:
# - iam:GenerateCredentialReport asks IAM to (re)build the account's credential report,
#   which GetCredentialReport then reads. It changes no configuration and AWS classifies
#   it as a Read-level action; it is part of the AWS-managed SecurityAudit policy.
READ_ONLY_EXCEPTIONS: frozenset[str] = frozenset({"iam:GenerateCredentialReport"})

# Rules declare IAM permission names (what the client must grant). The guard checks
# API operation names (what the SDK sends). They are the same except for these:
OPERATION_FOR_PERMISSION: dict[str, str] = {
    "s3:ListAllMyBuckets": "s3:ListBuckets",
    "s3:GetBucketPublicAccessBlock": "s3:GetPublicAccessBlock",
    "s3:GetAccountPublicAccessBlock": "s3:GetPublicAccessBlock",  # S3 Control API
}

# The platform's own identity may only do two things: say who it is, and request
# the client's read-only role. Nothing else.
PLATFORM_OPERATIONS: frozenset[str] = frozenset({"sts:GetCallerIdentity", "sts:AssumeRole"})

# Calls the connector itself makes inside a client account, beyond what rules need.
CONNECTOR_OPERATIONS: frozenset[str] = frozenset({"sts:GetCallerIdentity", "ec2:DescribeRegions"})


def assessment_permissions() -> frozenset[str]:
    """The IAM permissions the enabled rules declare (what clients must grant)."""
    return frozenset(
        permission
        for rule in ALL_RULES
        for permission in rule.metadata.required_permissions.get(Provider.AWS, ())
    )


def assessment_operations() -> frozenset[str]:
    """Every API operation allowed inside a client account: exactly what the enabled
    rules declare (translated to API names), plus the connector's own needs."""
    operations = frozenset(
        {OPERATION_FOR_PERMISSION.get(p, p) for p in assessment_permissions()}
        | CONNECTOR_OPERATIONS
    )
    not_reads = [
        op
        for op in operations
        if op not in READ_ONLY_EXCEPTIONS and not op.split(":", 1)[1].startswith(READ_PREFIXES)
    ]
    if not_reads:
        raise ValueError(f"non-read operations cannot be allowed in client accounts: {not_reads}")
    return operations


def _service_prefix(model: Any) -> str:
    # The IAM action prefix (e.g. "ec2", "cloudtrail", "sts") is botocore's signing name.
    service_model = model.service_model
    return service_model.signing_name or service_model.endpoint_prefix


def install_guard(session: boto3.Session, allowed: Iterable[str]) -> boto3.Session:
    """Attach the guard to a boto3 session. Every client created from this session
    afterwards is checked; returns the same session for convenience."""
    allowed_set = frozenset(allowed)

    def check(model: Any, **_: Any) -> None:
        operation = f"{_service_prefix(model)}:{model.name}"
        if operation not in allowed_set:
            raise ReadOnlyViolation(f"Blocked by read-only guard: {operation} is not allowed.")

    session.events.register(
        "before-parameter-build", check, unique_id="cloud-vuln-scan-read-only-guard"
    )
    return session


def guarded_session(allowed: Iterable[str], **session_kwargs: Any) -> boto3.Session:
    return install_guard(boto3.Session(**session_kwargs), allowed)
