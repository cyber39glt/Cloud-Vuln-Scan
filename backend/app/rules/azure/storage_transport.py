"""AZ-STO-002 / AZ-STO-003: storage account encryption in transit."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

_ACCOUNTS = {Provider.AZURE: ("azure.storage.account",)}
_READ = {Provider.AZURE: ("Microsoft.Storage/storageAccounts/read",)}

ACCEPTED_TLS = ("TLS1_2", "TLS1_3")


class StorageAccountAllowsHttp(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-STO-002",
        title="Storage account accepts unencrypted HTTP",
        category=Category.STORAGE,
        severity=Severity.MEDIUM,
        scope="resource",
        description="'Secure transfer required' is disabled, so the account accepts plain HTTP.",
        risk=(
            "Data and shared-key or SAS credentials sent over HTTP can be read or altered "
            "by anyone on the network path."
        ),
        recommendation=(
            "Enable 'Secure transfer required' (supportsHttpsTrafficOnly = true) so the "
            "account rejects unencrypted requests."
        ),
        required_resource_types=_ACCOUNTS,
        required_permissions=_READ,
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for account in self.resources(inventory):
            setting = account.properties.get("https_only")
            if setting is True:
                yield self.passed(account, "Secure transfer (HTTPS only) is required.")
                continue
            # Unknown is never a pass: Azure normally always reports this property.
            shown = "false" if setting is False else "not reported"
            yield self.failed(
                account,
                "Secure transfer is not required; HTTP is accepted.",
                [
                    self.evidence(
                        account,
                        f"supportsHttpsTrafficOnly is {shown}.",
                        {"https_only": setting},
                    )
                ],
            )


class StorageAccountWeakTls(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-STO-003",
        title="Storage account allows TLS older than 1.2",
        category=Category.STORAGE,
        severity=Severity.MEDIUM,
        scope="resource",
        description="The account's minimum TLS version permits TLS 1.0 or 1.1 connections.",
        risk=(
            "TLS 1.0 and 1.1 have known weaknesses and are deprecated. Allowing them lets "
            "outdated or downgraded clients connect with weaker protection."
        ),
        recommendation="Set the storage account's minimum TLS version to TLS 1.2.",
        required_resource_types=_ACCOUNTS,
        required_permissions=_READ,
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for account in self.resources(inventory):
            version = account.properties.get("minimum_tls_version")
            if version in ACCEPTED_TLS:
                yield self.passed(account, f"Minimum TLS version is {version}.")
                continue
            # Microsoft documents that an unset value means TLS 1.0 is accepted.
            shown = version or "not set (TLS 1.0 accepted)"
            yield self.failed(
                account,
                f"Minimum TLS version is {shown}.",
                [
                    self.evidence(
                        account,
                        f"minimumTlsVersion is {shown}.",
                        {"minimum_tls_version": version},
                    )
                ],
            )
