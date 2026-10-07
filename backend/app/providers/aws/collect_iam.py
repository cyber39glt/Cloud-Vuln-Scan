"""AWS IAM collection: account summary, password policy, credential report, and who
has the AdministratorAccess policy. IAM is global, so nothing here is per region.

API calls: iam:GetAccountSummary, iam:GetAccountPasswordPolicy,
iam:GenerateCredentialReport, iam:GetCredentialReport, iam:ListEntitiesForPolicy.

Data minimization: the credential report lists every user with dates. We keep, per
user, only: password enabled, MFA active, and per access key: active, last rotated,
last used. No key IDs or other fields are stored.
"""

import csv
import io
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Resource
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.session import CLIENT_CONFIG
from app.providers.common import ReadOnlyViolation

IAM_ACCOUNT = "aws.iam.account"
PASSWORD_POLICY = "aws.iam.password_policy"  # noqa: S105  a resource type name, not a password
IAM_USER = "aws.iam.user"
ADMIN_POLICY = "aws.iam.admin_policy"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

Collected = tuple[list[Resource], list[CollectionGap]]


def _code(error: Exception) -> str:
    return describe_aws_error(error).code


def _resource(
    account_id: str,
    resource_type: str,
    resource_id: str,
    name: str,
    properties: dict[str, Any],
    operation: str,
    collected_at: datetime,
) -> Resource:
    return Resource(
        provider=Provider.AWS,
        account_id=account_id,
        region="global",
        resource_type=resource_type,
        resource_id=resource_id,
        name=name,
        properties=properties,
        source_operation=operation,
        collected_at=collected_at,
    )


def _guarded(resource_type: str, collect: Callable[[], list[Resource]]) -> Collected:
    try:
        return collect(), []
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        return [], [CollectionGap(resource_type=resource_type, reason=_code(exc))]


# ------------------------------------------------------------------ account + policy


def _account_summary(iam: Any, account_id: str, collected_at: datetime) -> list[Resource]:
    summary = iam.get_account_summary()["SummaryMap"]
    return [
        _resource(
            account_id,
            IAM_ACCOUNT,
            f"arn:aws:iam::{account_id}:root",
            "root user",
            {
                "root_mfa_enabled": summary.get("AccountMFAEnabled") == 1,
                "root_access_keys_present": summary.get("AccountAccessKeysPresent", 0) > 0,
            },
            "iam:GetAccountSummary",
            collected_at,
        )
    ]


def _password_policy(iam: Any, account_id: str, collected_at: datetime) -> list[Resource]:
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        properties = {
            "exists": True,
            "minimum_length": policy.get("MinimumPasswordLength"),
            "require_symbols": policy.get("RequireSymbols"),
            "require_numbers": policy.get("RequireNumbers"),
            "require_uppercase": policy.get("RequireUppercaseCharacters"),
            "require_lowercase": policy.get("RequireLowercaseCharacters"),
            "reuse_prevention": policy.get("PasswordReusePrevention"),
        }
    except ClientError as exc:
        # "NoSuchEntity" is a real answer: the account has no password policy.
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
        properties = {"exists": False}
    return [
        _resource(
            account_id,
            PASSWORD_POLICY,
            f"arn:aws:iam::{account_id}:password-policy",
            "account password policy",
            properties,
            "iam:GetAccountPasswordPolicy",
            collected_at,
        )
    ]


# ------------------------------------------------------------------ credential report


def _report_date(value: str) -> str | None:
    """Credential report dates are ISO 8601, or 'N/A' / 'no_information'."""
    value = (value or "").strip()
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()


def _credential_report(
    iam: Any, sleep: Callable[[float], None], attempts: int = 10
) -> list[dict[str, str]]:
    """Ask IAM to build the report (it changes no configuration), wait, then read it."""
    for attempt in range(attempts):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        sleep(min(2**attempt, 5))
    else:
        raise TimeoutError("credential report not ready")
    content = iam.get_credential_report()["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return list(csv.DictReader(io.StringIO(text)))


def _users(
    iam: Any, account_id: str, collected_at: datetime, sleep: Callable[[float], None]
) -> list[Resource]:
    users = []
    for row in _credential_report(iam, sleep):
        if row.get("user") == "<root_account>":
            continue  # the root user is covered by the account summary
        keys = [
            {
                "slot": slot,
                "active": row.get(f"access_key_{slot}_active") == "true",
                "last_rotated": _report_date(row.get(f"access_key_{slot}_last_rotated", "")),
                "last_used": _report_date(row.get(f"access_key_{slot}_last_used_date", "")),
            }
            for slot in (1, 2)
        ]
        users.append(
            _resource(
                account_id,
                IAM_USER,
                row["arn"],
                row["user"],
                {
                    "password_enabled": row.get("password_enabled") == "true",
                    "mfa_active": row.get("mfa_active") == "true",
                    "access_keys": [k for k in keys if k["active"]],
                },
                "iam:GenerateCredentialReport, iam:GetCredentialReport",
                collected_at,
            )
        )
    return users


# ------------------------------------------------------------------ administrator access


def _admin_policy(iam: Any, account_id: str, collected_at: datetime) -> list[Resource]:
    users, groups, roles = [], [], []
    for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=ADMIN_POLICY_ARN):
        users += [u["UserName"] for u in page.get("PolicyUsers", [])]
        groups += [g["GroupName"] for g in page.get("PolicyGroups", [])]
        roles += [r["RoleName"] for r in page.get("PolicyRoles", [])]
    return [
        _resource(
            account_id,
            ADMIN_POLICY,
            ADMIN_POLICY_ARN,
            "AdministratorAccess",
            {"users": sorted(users), "groups": sorted(groups), "roles": sorted(roles)},
            "iam:ListEntitiesForPolicy",
            collected_at,
        )
    ]


def collect_iam(
    session: Any,
    account_id: str,
    collected_at: datetime,
    sleep: Callable[[float], None] | None = None,
) -> Collected:
    sleep = sleep or time.sleep  # looked up at call time, so tests can replace it
    iam = session.client("iam", config=CLIENT_CONFIG)
    resources: list[Resource] = []
    gaps: list[CollectionGap] = []
    for resource_type, collect in (
        (IAM_ACCOUNT, lambda: _account_summary(iam, account_id, collected_at)),
        (PASSWORD_POLICY, lambda: _password_policy(iam, account_id, collected_at)),
        (IAM_USER, lambda: _users(iam, account_id, collected_at, sleep)),
        (ADMIN_POLICY, lambda: _admin_policy(iam, account_id, collected_at)),
    ):
        found, missing = _guarded(resource_type, collect)
        resources += found
        gaps += missing
    return resources, gaps
