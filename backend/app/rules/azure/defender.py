"""AZ-SEC-001: key Microsoft Defender for Cloud plans are not enabled."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

KEY_PLANS = ("VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults")


class DefenderPlansDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-SEC-001",
        title="Key Microsoft Defender for Cloud plans are not enabled",
        category=Category.LOGGING_MONITORING,
        severity=Severity.MEDIUM,
        scope="account",
        description=(
            "One or more Defender plans for servers, SQL, storage or Key Vault is on the "
            "Free tier for the subscription."
        ),
        risk=(
            "Without these plans Azure does not raise threat-detection alerts (for "
            "example malware uploads, SQL injection or unusual Key Vault access), so "
            "attacks can go unnoticed."
        ),
        recommendation=(
            "Enable the Standard tier for the Defender plans that match the workloads in "
            "the subscription and route the alerts to the security team."
        ),
        required_resource_types={Provider.AZURE: ("azure.security.defender_plans",)},
        required_permissions={Provider.AZURE: ("Microsoft.Security/pricings/read",)},
        limitations=(
            "Checks only the four plans listed; it does not judge whether a plan is "
            "relevant if the subscription has no resources of that kind. Plans have a cost.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for defender in self.resources(inventory):
            plans = defender.properties.get("plans", {})
            off = {plan: plans.get(plan) for plan in KEY_PLANS if plans.get(plan) != "Standard"}
            if not off:
                yield self.passed(inventory, "All key Defender plans are on Standard.")
                continue
            yield self.failed(
                inventory,
                f"{len(off)} of {len(KEY_PLANS)} key Defender plans are not enabled: "
                f"{', '.join(off)}.",
                [
                    self.evidence(
                        defender,
                        "Plans not on the Standard tier (None = not returned by Azure).",
                        {"not_standard": off},
                    )
                ],
            )
