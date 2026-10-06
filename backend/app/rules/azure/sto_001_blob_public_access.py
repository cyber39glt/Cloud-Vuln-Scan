"""AZ-STO-001: storage account permits anonymous (public) blob access.

A provider-specific rule reading one Azure property: `allowBlobPublicAccess`.
"""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult, Evidence
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata


class StorageAccountAllowsPublicBlobAccess(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-STO-001",
        title="Storage account allows anonymous blob access",
        category=Category.STORAGE,
        severity=Severity.MEDIUM,
        scope="resource",
        description=(
            "The storage account's 'Allow Blob anonymous access' setting is enabled (or "
            "was never set, which Azure treats as enabled). Containers in the account can "
            "then be made readable by anyone on the internet without authentication."
        ),
        risk=(
            "A single container mistakenly set to public exposes its data to the whole "
            "internet. Disabling anonymous access at the account level prevents this "
            "class of mistake entirely."
        ),
        recommendation=(
            "Set 'Allow Blob anonymous access' to Disabled on the storage account "
            "(property allowBlobPublicAccess = false). Use SAS tokens or Entra ID "
            "authorization for any legitimate external sharing."
        ),
        required_resource_types={Provider.AZURE: ("azure.storage.account",)},
        required_permissions={Provider.AZURE: ("Microsoft.Storage/storageAccounts/read",)},
        limitations=(
            "Checks the account-level setting only. It does not list containers to "
            "confirm whether any container is actually public; that check is planned.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for account in self.resources(inventory):
            setting = account.properties.get("allow_blob_public_access")
            if setting is False:
                yield self.passed(account, "Anonymous blob access is disabled.")
                continue

            # Microsoft documents that a missing (null) value permits public access.
            explanation = (
                "is enabled" if setting is True else "is not set (Azure treats this as enabled)"
            )
            evidence = Evidence(
                source_operation=account.source_operation,
                collected_at=account.collected_at,
                summary=f"allowBlobPublicAccess {explanation}.",
                observed={"allow_blob_public_access": setting},
            )
            yield self.failed(account, f"Anonymous blob access {explanation}.", [evidence])
