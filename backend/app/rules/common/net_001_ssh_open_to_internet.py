"""NET-001: SSH reachable from the whole internet (AWS and Azure)."""

from collections.abc import Iterator

from app.domain.enums import Category, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata
from app.rules.common._port_exposure import (
    FIREWALL_LIMITATIONS,
    FIREWALL_READ_PERMISSIONS,
    FIREWALL_RESOURCE_TYPES,
    evaluate_port_exposure,
)


class SshOpenToInternet(Rule):
    metadata = RuleMetadata(
        rule_id="NET-001",
        title="SSH open to the internet",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        scope="resource",
        description="A firewall rule allows inbound SSH (TCP 22) from any address on the internet.",
        risk=(
            "Anyone on the internet can attempt to log in to the servers this firewall "
            "protects. Exposed SSH is constantly targeted by automated password and key "
            "guessing and by exploits for SSH server vulnerabilities."
        ),
        recommendation=(
            "Remove the rule, or restrict its source to specific trusted address ranges. "
            "Prefer access through a bastion host, VPN, AWS Systems Manager Session Manager "
            "or Azure Bastion instead of exposing SSH."
        ),
        required_resource_types=FIREWALL_RESOURCE_TYPES,
        required_permissions=FIREWALL_READ_PERMISSIONS,
        limitations=FIREWALL_LIMITATIONS,
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        return evaluate_port_exposure(self, inventory, port=22, service="SSH")
