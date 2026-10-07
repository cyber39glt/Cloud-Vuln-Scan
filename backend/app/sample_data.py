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


def _aws(
    resource_type: str,
    resource_id: str,
    name: str,
    properties: dict,
    operation: str,
    region: str = "global",
) -> Resource:
    return Resource(
        provider=Provider.AWS,
        account_id=AWS_ACCOUNT,
        region=region,
        resource_type=resource_type,
        resource_id=resource_id,
        name=name,
        properties=properties,
        source_operation=operation,
        collected_at=COLLECTED_AT,
    )


def _aws_account_resources() -> list[Resource]:
    """IAM, S3 and RDS: a typical small account with a few common weaknesses."""
    iam = f"arn:aws:iam::{AWS_ACCOUNT}"
    report = "iam:GenerateCredentialReport, iam:GetCredentialReport"
    stale_key = {
        "slot": 1,
        "active": True,
        "last_rotated": "2024-03-01T10:00:00+00:00",
        "last_used": "2025-06-30T08:15:00+00:00",
    }
    blocked = dict.fromkeys(
        ("block_public_acls", "ignore_public_acls", "block_public_policy"), True
    )
    return [
        _aws(
            "aws.iam.account",
            f"{iam}:root",
            "root user",
            {"root_mfa_enabled": True, "root_access_keys_present": False},
            "iam:GetAccountSummary",
        ),
        _aws(
            "aws.iam.password_policy",
            f"{iam}:password-policy",
            "account password policy",
            {"exists": True, "minimum_length": 8},
            "iam:GetAccountPasswordPolicy",
        ),
        _aws(
            "aws.iam.user",
            f"{iam}:user/alice",
            "alice",
            {"password_enabled": True, "mfa_active": False, "access_keys": []},
            report,
        ),
        _aws(
            "aws.iam.user",
            f"{iam}:user/ci-deploy",
            "ci-deploy",
            {"password_enabled": False, "mfa_active": False, "access_keys": [stale_key]},
            report,
        ),
        _aws(
            "aws.iam.admin_policy",
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "AdministratorAccess",
            {"users": ["alice"], "groups": [], "roles": ["Admin"]},
            "iam:ListEntitiesForPolicy",
        ),
        _aws(
            "aws.s3.account_settings",
            f"arn:aws:s3:::account/{AWS_ACCOUNT}",
            "S3 account settings",
            {**blocked, "restrict_public_buckets": False},
            "s3:GetAccountPublicAccessBlock",
        ),
        _aws(
            "aws.s3.bucket",
            "arn:aws:s3:::demo-public-assets",
            "demo-public-assets",
            {
                "policy_public": True,
                "acl_public": False,
                **dict.fromkeys((*blocked, "restrict_public_buckets"), False),
            },
            "s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetPublicAccessBlock",
            region="eu-west-2",
        ),
        _aws(
            "aws.rds.db_instance",
            f"arn:aws:rds:eu-west-2:{AWS_ACCOUNT}:db:orders-db",
            "orders-db",
            {"engine": "postgres", "publicly_accessible": True},
            "rds:DescribeDBInstances",
            region="eu-west-2",
        ),
    ]


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
        *_aws_account_resources(),
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
            properties={
                "allow_blob_public_access": None,
                "https_only": True,
                "minimum_tls_version": "TLS1_0",
            },
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
            properties={
                "allow_blob_public_access": False,
                "https_only": True,
                "minimum_tls_version": "TLS1_2",
            },
            source_operation="Microsoft.Storage/storageAccounts/read",
            collected_at=COLLECTED_AT,
        ),
        Resource(
            provider=Provider.AZURE,
            account_id=AZURE_SUBSCRIPTION,
            region="uksouth",
            resource_type="azure.sql.server",
            resource_id=f"{_AZURE_RG}/Microsoft.Sql/servers/demo-sql",
            name="demo-sql",
            properties={
                "public_network_access": "Enabled",
                "firewall_rules": [
                    {
                        "name": "AllowAllWindowsAzureIps",
                        "start_ip": "0.0.0.0",  # noqa: S104  firewall data, not a binding
                        "end_ip": "0.0.0.0",  # noqa: S104
                    }
                ],
            },
            source_operation="Microsoft.Sql/servers/read, Microsoft.Sql/servers/firewallRules/read",
            collected_at=COLLECTED_AT,
        ),
        Resource(
            provider=Provider.AZURE,
            account_id=AZURE_SUBSCRIPTION,
            region="global",
            resource_type="azure.monitor.activity_log_export",
            resource_id=(
                f"/subscriptions/{AZURE_SUBSCRIPTION}/providers/Microsoft.Insights/diagnosticSettings"
            ),
            name="Activity Log diagnostic settings",
            properties={"settings": []},
            source_operation="Microsoft.Insights/diagnosticSettings/read",
            collected_at=COLLECTED_AT,
        ),
        Resource(
            provider=Provider.AZURE,
            account_id=AZURE_SUBSCRIPTION,
            region="global",
            resource_type="azure.security.defender_plans",
            resource_id=f"/subscriptions/{AZURE_SUBSCRIPTION}/providers/Microsoft.Security/pricings",
            name="Microsoft Defender for Cloud plans",
            properties={
                "plans": {
                    "KeyVaults": "Free",
                    "SqlServers": "Standard",
                    "StorageAccounts": "Standard",
                    "VirtualMachines": "Standard",
                }
            },
            source_operation="Microsoft.Security/pricings/read",
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
