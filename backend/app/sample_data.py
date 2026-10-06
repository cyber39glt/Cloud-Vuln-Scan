"""Hand-made sample inventories for the demo and tests.

These imitate what the AWS and Azure collectors (M3, M7) will produce. All IDs are
fictional: AWS documentation-style account 111122223333, a zeroed Azure subscription.
"""

from datetime import UTC, datetime

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Inventory, NetworkIngressRule, Resource

COLLECTED_AT = datetime(2026, 1, 15, 9, 30, tzinfo=UTC)
AWS_ACCOUNT = "111122223333"
AZURE_SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
_AZURE_RG = f"/subscriptions/{AZURE_SUBSCRIPTION}/resourceGroups/demo-rg/providers"


def _sg(name: str, group_id: str, region: str, rules: list[NetworkIngressRule]) -> Resource:
    return Resource(
        provider=Provider.AWS,
        account_id=AWS_ACCOUNT,
        region=region,
        resource_type="aws.ec2.security_group",
        resource_id=f"arn:aws:ec2:{region}:{AWS_ACCOUNT}:security-group/{group_id}",
        name=name,
        ingress_rules=tuple(rules),
        source_operation="ec2:DescribeSecurityGroups",
        collected_at=COLLECTED_AT,
    )


def sample_aws_inventory() -> Inventory:
    resources = [
        _sg(
            "web-servers",
            "sg-0a1b2c3d4e5f60001",
            "eu-west-2",
            [
                NetworkIngressRule(protocol="tcp", port_from=443, port_to=443, source="0.0.0.0/0"),
                NetworkIngressRule(protocol="tcp", port_from=22, port_to=22, source="0.0.0.0/0"),
            ],
        ),
        _sg(
            "legacy-windows",
            "sg-0a1b2c3d4e5f60002",
            "eu-west-2",
            [NetworkIngressRule(protocol="tcp", port_from=3389, port_to=3389, source="::/0")],
        ),
        _sg(
            "internal-admin",
            "sg-0a1b2c3d4e5f60003",
            "eu-west-2",
            [NetworkIngressRule(protocol="tcp", port_from=22, port_to=22, source="10.0.0.0/8")],
        ),
        Resource(
            provider=Provider.AWS,
            account_id=AWS_ACCOUNT,
            region="eu-west-2",
            resource_type="aws.cloudtrail.trail",
            resource_id=f"arn:aws:cloudtrail:eu-west-2:{AWS_ACCOUNT}:trail/app-trail",
            name="app-trail",
            properties={"is_multi_region": False, "is_logging": True},
            source_operation="cloudtrail:DescribeTrails",
            collected_at=COLLECTED_AT,
        ),
    ]
    return Inventory(
        provider=Provider.AWS,
        account_id=AWS_ACCOUNT,
        regions=("eu-west-2", "us-east-1"),
        collected_at=COLLECTED_AT,
        resources=tuple(resources),
        # Simulates a region where the role was not allowed to list security groups.
        gaps=(
            CollectionGap(
                resource_type="aws.ec2.security_group",
                region="us-east-1",
                reason="AccessDenied",
            ),
        ),
    )


def sample_azure_inventory() -> Inventory:
    resources = [
        Resource(
            provider=Provider.AZURE,
            account_id=AZURE_SUBSCRIPTION,
            region="uksouth",
            resource_type="azure.network.nsg",
            resource_id=f"{_AZURE_RG}/Microsoft.Network/networkSecurityGroups/jumpbox-nsg",
            name="jumpbox-nsg",
            ingress_rules=(
                NetworkIngressRule(
                    protocol="tcp",
                    port_from=3389,
                    port_to=3389,
                    source="Internet",
                    priority=300,
                    rule_name="Allow-RDP",
                ),
            ),
            source_operation="Microsoft.Network/networkSecurityGroups/read",
            collected_at=COLLECTED_AT,
        ),
        Resource(
            provider=Provider.AZURE,
            account_id=AZURE_SUBSCRIPTION,
            region="uksouth",
            resource_type="azure.storage.account",
            resource_id=f"{_AZURE_RG}/Microsoft.Storage/storageAccounts/demopublicdata",
            name="demopublicdata",
            properties={"allow_blob_public_access": None},
            source_operation="Microsoft.Storage/storageAccounts/read",
            collected_at=COLLECTED_AT,
        ),
        Resource(
            provider=Provider.AZURE,
            account_id=AZURE_SUBSCRIPTION,
            region="uksouth",
            resource_type="azure.storage.account",
            resource_id=f"{_AZURE_RG}/Microsoft.Storage/storageAccounts/demoprivatedata",
            name="demoprivatedata",
            properties={"allow_blob_public_access": False},
            source_operation="Microsoft.Storage/storageAccounts/read",
            collected_at=COLLECTED_AT,
        ),
    ]
    return Inventory(
        provider=Provider.AZURE,
        account_id=AZURE_SUBSCRIPTION,
        regions=("uksouth",),
        collected_at=COLLECTED_AT,
        resources=tuple(resources),
    )
