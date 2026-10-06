"""NET-001: SSH or RDP reachable from the whole internet.

One rule for both clouds: it reads the normalized `NetworkIngressRule` facet, which
collectors fill from AWS security group rules and Azure NSG rules alike.
"""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult, Evidence
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

MANAGEMENT_PORTS = {22: "SSH", 3389: "RDP"}


class ManagementPortsOpenToInternet(Rule):
    metadata = RuleMetadata(
        rule_id="NET-001",
        title="Remote administration ports open to the internet",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        scope="resource",
        description=(
            "A firewall rule allows inbound SSH (TCP 22) or RDP (TCP 3389) traffic from any "
            "address on the internet."
        ),
        risk=(
            "Anyone on the internet can attempt to log in to the servers this firewall "
            "protects. Exposed SSH and RDP are constantly targeted by automated password "
            "guessing and by exploits for remote-access vulnerabilities."
        ),
        recommendation=(
            "Remove the rule, or restrict its source to specific trusted address ranges. "
            "Prefer access through a bastion host, VPN, AWS Systems Manager Session Manager "
            "or Azure Bastion instead of exposing management ports."
        ),
        required_resource_types={
            Provider.AWS: ("aws.ec2.security_group",),
            Provider.AZURE: ("azure.network.nsg",),
        },
        required_permissions={
            Provider.AWS: ("ec2:DescribeSecurityGroups",),
            Provider.AZURE: ("Microsoft.Network/networkSecurityGroups/read",),
        },
        limitations=(
            "Azure: an allow rule is reported even if a higher-priority deny rule in the "
            "same NSG blocks the same traffic. Effective-rule calculation is planned.",
            "Does not check whether the security group or NSG is attached to a running resource.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for resource in self.resources(inventory):
            exposing = [
                (rule, port)
                for rule in resource.ingress_rules
                if rule.action == "allow" and rule.is_from_internet
                for port in MANAGEMENT_PORTS
                if rule.covers_port(port)
            ]
            if not exposing:
                yield self.passed(resource, "No inbound SSH or RDP allowed from the internet.")
                continue

            services = sorted({MANAGEMENT_PORTS[port] for _, port in exposing})
            offending_rules = list(dict.fromkeys(rule for rule, _ in exposing))
            evidence = Evidence(
                source_operation=resource.source_operation,
                collected_at=resource.collected_at,
                summary=(
                    f"{len(offending_rules)} inbound rule(s) allow "
                    f"{' and '.join(services)} from the internet."
                ),
                observed={
                    "inbound_rules": [
                        rule.model_dump(exclude_none=True) for rule in offending_rules
                    ]
                },
            )
            yield self.failed(
                resource,
                f"{' and '.join(services)} open to the internet.",
                [evidence],
            )
