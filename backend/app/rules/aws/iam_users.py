"""AWS-IAM-003 / AWS-IAM-004: IAM users from the credential report."""

from collections.abc import Iterator
from datetime import datetime, timedelta

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

_USERS = {Provider.AWS: ("aws.iam.user",)}
_REPORT = {Provider.AWS: ("iam:GenerateCredentialReport", "iam:GetCredentialReport")}

UNUSED_DAYS = 45  # CIS AWS Foundations threshold for unused credentials


class ConsoleUserWithoutMfa(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-IAM-003",
        title="IAM user can sign in to the console without MFA",
        category=Category.IDENTITY_ACCESS,
        severity=Severity.HIGH,
        scope="resource",
        description="An IAM user has a console password but no multi-factor authentication.",
        risk=(
            "Passwords are phished, reused and guessed. Without MFA, one stolen password "
            "gives an attacker this user's full console access."
        ),
        recommendation=(
            "Require MFA for every IAM user with a console password, or remove console "
            "access and move people to IAM Identity Center (SSO) with enforced MFA."
        ),
        required_resource_types=_USERS,
        required_permissions=_REPORT,
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for user in self.resources(inventory):
            props = user.properties
            if not props.get("password_enabled"):
                yield self.passed(user, "No console password.")
            elif props.get("mfa_active"):
                yield self.passed(user, "Console password with MFA.")
            else:
                yield self.failed(
                    user,
                    "Console password without MFA.",
                    [
                        self.evidence(
                            user,
                            "Credential report: password_enabled=true, mfa_active=false.",
                            {"password_enabled": True, "mfa_active": False},
                        )
                    ],
                )


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class UnusedAccessKeys(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-IAM-004",
        title=f"Active access keys unused for {UNUSED_DAYS}+ days",
        category=Category.IDENTITY_ACCESS,
        severity=Severity.MEDIUM,
        scope="resource",
        description=(
            f"An IAM user has an active access key that has not been used for at least "
            f"{UNUSED_DAYS} days (or never, and is older than that)."
        ),
        risk=(
            "Forgotten keys are rarely monitored and often end up in old scripts, "
            "backups or repositories. Each one is a standing way into the account."
        ),
        recommendation=(
            "Deactivate, then delete, access keys that are no longer used. Prefer IAM "
            "roles and temporary credentials over long-lived keys."
        ),
        required_resource_types=_USERS,
        required_permissions=_REPORT,
        limitations=("Keys created within the last 45 days and never used are not reported.",),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        cutoff = inventory.collected_at - timedelta(days=UNUSED_DAYS)
        for user in self.resources(inventory):
            stale = []
            for key in user.properties.get("access_keys", []):
                last_used = _parse(key.get("last_used"))
                last_rotated = _parse(key.get("last_rotated"))
                reference = last_used or last_rotated
                if reference is not None and reference < cutoff:
                    stale.append(key)
            if not stale:
                yield self.passed(user, "No active access keys unused for 45+ days.")
                continue
            yield self.failed(
                user,
                f"{len(stale)} active access key(s) unused for {UNUSED_DAYS}+ days.",
                [
                    self.evidence(
                        user,
                        f"Credential report: active key(s) last used before {cutoff:%Y-%m-%d}.",
                        {"stale_keys": stale},
                    )
                ],
            )
