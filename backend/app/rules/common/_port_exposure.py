"""Shared logic for "port X open to the internet" rules (NET-001 SSH, NET-002 RDP).

Works for both clouds: it reads the normalized `NetworkIngressRule` facet, which
collectors fill from AWS security group rules and Azure NSG rules alike.
"""

from collections.abc import Iterator

from app.domain.enums import Provider
from app.domain.findings import CheckResult, Evidence
from app.domain.inventory import Inventory
from app.rules.base import Rule

FIREWALL_RESOURCE_TYPES = {
    Provider.AWS: ("aws.ec2.security_group",),
    Provider.AZURE: ("azure.network.nsg",),
}
FIREWALL_READ_PERMISSIONS = {
    Provider.AWS: ("ec2:DescribeSecurityGroups",),
    Provider.AZURE: ("Microsoft.Network/networkSecurityGroups/read",),
}
FIREWALL_LIMITATIONS = (
    "Azure: an allow rule is reported even if a higher-priority deny rule in the same NSG "
    "blocks the same traffic. Effective-rule calculation is planned.",
    "Does not check whether the security group or NSG is attached to a running resource.",
)


def evaluate_port_exposure(
    rule: Rule, inventory: Inventory, port: int, service: str
) -> Iterator[CheckResult]:
    for resource in rule.resources(inventory):
        offending = [
            ingress
            for ingress in resource.ingress_rules
            if ingress.action == "allow" and ingress.is_from_internet and ingress.covers_port(port)
        ]
        if not offending:
            yield rule.passed(resource, f"No inbound {service} allowed from the internet.")
            continue

        evidence = Evidence(
            source_operation=resource.source_operation,
            collected_at=resource.collected_at,
            summary=f"{len(offending)} inbound rule(s) allow {service} (TCP {port}) "
            "from the internet.",
            observed={"inbound_rules": [i.model_dump(exclude_none=True) for i in offending]},
        )
        yield rule.failed(resource, f"{service} (TCP {port}) open to the internet.", [evidence])
