"""AWS-LOG-001: no multi-region CloudTrail trail that is actively logging.

An account-level rule: it judges the account as a whole ("does ANY trail cover all
regions?"). Because it concludes from the *absence* of something, the engine refuses
to run it when trail data could not be collected, so a permissions problem can never
look like "no CloudTrail".
"""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult, Evidence
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata


class CloudTrailMultiRegionLogging(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-LOG-001",
        title="No multi-region CloudTrail trail is logging",
        category=Category.LOGGING_MONITORING,
        severity=Severity.HIGH,
        scope="account",
        description=(
            "The account has no CloudTrail trail that both covers all regions and is "
            "currently logging."
        ),
        risk=(
            "Without a multi-region trail, API activity in some regions, including "
            "activity by an attacker using stolen credentials, is not recorded. "
            "Investigations and incident response lose the audit trail they depend on."
        ),
        recommendation=(
            "Create (or enable) a trail with 'multi-region' turned on, make sure logging "
            "is started, and deliver logs to a protected S3 bucket. In AWS Organizations, "
            "an organization trail from the management account satisfies this."
        ),
        required_resource_types={Provider.AWS: ("aws.cloudtrail.trail",)},
        required_permissions={
            Provider.AWS: ("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"),
        },
        limitations=(
            "Does not yet verify which event types the trail records, log file "
            "validation, or log encryption; separate checks are planned.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        trails = self.resources(inventory)
        compliant = [
            t
            for t in trails
            if t.properties.get("is_multi_region") is True
            and t.properties.get("is_logging") is True
        ]
        if compliant:
            names = ", ".join(sorted(t.name for t in compliant))
            yield self.passed(inventory, f"Multi-region trail(s) logging: {names}.")
            return

        evidence = Evidence(
            source_operation="cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
            collected_at=inventory.collected_at,
            summary=(
                "No trails found."
                if not trails
                else f"{len(trails)} trail(s) found; none is both multi-region and logging."
            ),
            observed={
                "trails": [
                    {
                        "name": t.name,
                        "home_region": t.region,
                        "is_multi_region": t.properties.get("is_multi_region"),
                        "is_logging": t.properties.get("is_logging"),
                    }
                    for t in sorted(trails, key=lambda t: t.name)
                ]
            },
        )
        yield self.failed(
            inventory, "No multi-region CloudTrail trail is actively logging.", [evidence]
        )
