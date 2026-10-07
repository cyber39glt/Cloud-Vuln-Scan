"""AZ-LOG-001: the subscription Activity Log is not exported."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

# The categories recording who changed what, and security alerts. "allLogs" (a
# category group) includes them.
REQUIRED_CATEGORIES = frozenset({"Administrative", "Security"})


def _covers(setting: dict) -> bool:
    categories = set(setting.get("enabled_categories", []))
    return bool(setting.get("has_destination")) and (
        "allLogs" in categories or categories >= REQUIRED_CATEGORIES
    )


class ActivityLogNotExported(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-LOG-001",
        title="Subscription Activity Log is not exported",
        category=Category.LOGGING_MONITORING,
        severity=Severity.MEDIUM,
        scope="account",
        description=(
            "No subscription diagnostic setting sends the Administrative and Security "
            "Activity Log categories to a Log Analytics workspace, storage account or "
            "event hub."
        ),
        risk=(
            "Azure keeps the Activity Log for only 90 days and it cannot be queried "
            "alongside other logs. Investigations of older or correlated activity lose "
            "their audit trail."
        ),
        recommendation=(
            "Create a subscription diagnostic setting that exports at least the "
            "Administrative and Security categories (or 'allLogs') to a protected "
            "destination."
        ),
        required_resource_types={Provider.AZURE: ("azure.monitor.activity_log_export",)},
        required_permissions={Provider.AZURE: ("Microsoft.Insights/diagnosticSettings/read",)},
        limitations=(
            "Does not check retention at the destination or exports configured at the "
            "management group or tenant level.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for export in self.resources(inventory):
            settings = export.properties.get("settings", [])
            covering = sorted(s.get("name") or "?" for s in settings if _covers(s))
            if covering:
                yield self.passed(inventory, f"Exported by: {', '.join(covering)}.")
                continue
            summary = (
                "No subscription diagnostic settings exist."
                if not settings
                else f"{len(settings)} setting(s) found; none exports the required categories."
            )
            yield self.failed(
                inventory,
                "Activity Log is not exported.",
                [self.evidence(export, summary, {"settings": settings})],
            )
