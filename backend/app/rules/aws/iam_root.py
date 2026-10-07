"""AWS-IAM-001 / AWS-IAM-002: the root user (the account's all-powerful login)."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

_ACCOUNT = {Provider.AWS: ("aws.iam.account",)}
_SUMMARY = {Provider.AWS: ("iam:GetAccountSummary",)}


class RootAccountWithoutMfa(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-IAM-001",
        title="Root user has no multi-factor authentication",
        category=Category.IDENTITY_ACCESS,
        severity=Severity.CRITICAL,
        scope="account",
        description="The AWS account's root user can sign in with a password alone.",
        risk=(
            "The root user can do anything in the account, including closing it and "
            "removing every other user's access. A stolen or guessed password gives an "
            "attacker complete, unrecoverable control."
        ),
        recommendation=(
            "Enable MFA on the root user (a hardware key or authenticator app), store the "
            "credentials securely, and stop using root for day-to-day work."
        ),
        required_resource_types=_ACCOUNT,
        required_permissions=_SUMMARY,
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for account in self.resources(inventory):
            if account.properties.get("root_mfa_enabled") is True:
                yield self.passed(inventory, "Root user has MFA enabled.")
            else:
                yield self.failed(
                    inventory,
                    "Root user has no MFA.",
                    [
                        self.evidence(
                            account, "AccountMFAEnabled is 0.", {"root_mfa_enabled": False}
                        )
                    ],
                )


class RootAccountAccessKeys(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-IAM-002",
        title="Root user has access keys",
        category=Category.IDENTITY_ACCESS,
        severity=Severity.CRITICAL,
        scope="account",
        description="Programmatic access keys exist for the AWS account's root user.",
        risk=(
            "Root access keys give unrestricted, non-revocable-by-policy control of the "
            "whole account to anyone who obtains them, for example from a leaked script, "
            "laptop or repository."
        ),
        recommendation=(
            "Delete the root user's access keys. Use IAM roles or IAM Identity Center for "
            "programmatic and administrative access instead."
        ),
        required_resource_types=_ACCOUNT,
        required_permissions=_SUMMARY,
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for account in self.resources(inventory):
            if account.properties.get("root_access_keys_present") is False:
                yield self.passed(inventory, "Root user has no access keys.")
            else:
                yield self.failed(
                    inventory,
                    "Root user has active access keys.",
                    [
                        self.evidence(
                            account,
                            "AccountAccessKeysPresent is greater than 0.",
                            {"root_access_keys_present": True},
                        )
                    ],
                )
