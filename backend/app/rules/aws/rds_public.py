"""AWS-EXP-001: RDS database instances that are publicly accessible."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata


class RdsInstancePublic(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-EXP-001",
        title="RDS database is publicly accessible",
        category=Category.EXPOSURE,
        severity=Severity.HIGH,
        scope="resource",
        description=(
            "The database instance has 'Publicly accessible' enabled, so it gets a public "
            "IP address and DNS name reachable from the internet."
        ),
        risk=(
            "Databases exposed to the internet are scanned continuously for weak passwords "
            "and engine vulnerabilities. A database should be reachable only from the "
            "applications that use it."
        ),
        recommendation=(
            "Turn off 'Publicly accessible', place the instance in private subnets, and "
            "allow access only from application security groups or through a bastion/VPN."
        ),
        required_resource_types={Provider.AWS: ("aws.rds.db_instance",)},
        required_permissions={Provider.AWS: ("rds:DescribeDBInstances",)},
        limitations=(
            "Does not evaluate whether security groups or routing actually permit "
            "internet traffic; a publicly accessible flag is reported on its own.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for db in self.resources(inventory):
            if not db.properties.get("publicly_accessible"):
                yield self.passed(db, "Not publicly accessible.")
                continue
            yield self.failed(
                db,
                "Database is publicly accessible.",
                [
                    self.evidence(
                        db,
                        "PubliclyAccessible is true.",
                        {"publicly_accessible": True, "engine": db.properties.get("engine")},
                    )
                ],
            )
