"""AZ-EXP-001 / AZ-EXP-002: Azure SQL server firewall exposure."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory, Resource
from app.rules.base import Rule, RuleMetadata

_SERVERS = {Provider.AZURE: ("azure.sql.server",)}
_READ = {
    Provider.AZURE: (
        "Microsoft.Sql/servers/read",
        "Microsoft.Sql/servers/firewallRules/read",
    )
}


def _matching_rules(server: Resource, start: str, end: str) -> list[dict]:
    """Firewall rules with this exact range, unless public network access is off.

    With publicNetworkAccess 'Disabled' Azure ignores IP firewall rules entirely.
    """
    if server.properties.get("public_network_access") == "Disabled":
        return []
    return [
        rule
        for rule in server.properties.get("firewall_rules", [])
        if rule.get("start_ip") == start and rule.get("end_ip") == end
    ]


class SqlServerOpenToInternet(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-EXP-001",
        title="Azure SQL server firewall allows the entire internet",
        category=Category.EXPOSURE,
        severity=Severity.HIGH,
        scope="resource",
        description=(
            "A server-level firewall rule allows 0.0.0.0 to 255.255.255.255 and public "
            "network access is enabled."
        ),
        risk=(
            "Every database on the server can be reached from any IP address, exposing "
            "it to password guessing and attacks on the database engine."
        ),
        recommendation=(
            "Delete the all-addresses firewall rule. Allow only specific client IP ranges, "
            "or use private endpoints and disable public network access."
        ),
        required_resource_types=_SERVERS,
        required_permissions=_READ,
        limitations=(
            "Flags only the exact all-addresses range; other very wide ranges and "
            "database-level firewall rules are not assessed.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for server in self.resources(inventory):
            rules = _matching_rules(server, "0.0.0.0", "255.255.255.255")  # noqa: S104
            if not rules:
                yield self.passed(server, "No firewall rule open to all internet addresses.")
                continue
            yield self.failed(
                server,
                "Firewall allows all internet addresses.",
                [
                    self.evidence(
                        server,
                        "Firewall rule(s) covering 0.0.0.0-255.255.255.255.",
                        {
                            "public_network_access": server.properties.get("public_network_access"),
                            "rules": rules,
                        },
                    )
                ],
            )


class SqlServerAllowsAllAzureServices(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-EXP-002",
        title="Azure SQL server allows access from all Azure services",
        category=Category.EXPOSURE,
        severity=Severity.MEDIUM,
        scope="resource",
        description=(
            "The 'Allow Azure services and resources to access this server' setting (a "
            "0.0.0.0 to 0.0.0.0 firewall rule) is on."
        ),
        risk=(
            "The rule admits connections from any Azure resource, including resources "
            "in other customers' subscriptions, leaving the password as the only barrier."
        ),
        recommendation=(
            "Turn the setting off and allow the specific services that need access "
            "through virtual network rules or private endpoints."
        ),
        required_resource_types=_SERVERS,
        required_permissions=_READ,
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for server in self.resources(inventory):
            rules = _matching_rules(server, "0.0.0.0", "0.0.0.0")  # noqa: S104
            if not rules:
                yield self.passed(server, "Access from all Azure services is not allowed.")
                continue
            yield self.failed(
                server,
                "Access from all Azure services is allowed.",
                [
                    self.evidence(
                        server,
                        "Firewall rule 0.0.0.0-0.0.0.0 (all Azure services) is present.",
                        {"rules": rules},
                    )
                ],
            )
