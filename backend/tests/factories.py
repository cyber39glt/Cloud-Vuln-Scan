"""Small builders for test inventories, so each test shows only what matters to it."""

from datetime import UTC, datetime
from typing import Any

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Inventory, NetworkIngressRule, Resource

NOW = datetime(2026, 1, 15, 9, 30, tzinfo=UTC)
ACCOUNTS = {Provider.AWS: "111122223333", Provider.AZURE: "00000000-0000-0000-0000-000000000000"}


def ingress(
    port: int | tuple[int, int] = 22,
    source: str = "0.0.0.0/0",
    protocol: str = "tcp",
    action: str = "allow",
    **extra: Any,
) -> NetworkIngressRule:
    port_from, port_to = port if isinstance(port, tuple) else (port, port)
    return NetworkIngressRule(
        protocol=protocol,
        port_from=port_from,
        port_to=port_to,
        source=source,
        action=action,
        **extra,
    )


def resource(
    provider: Provider,
    resource_type: str,
    name: str,
    *,
    region: str = "eu-west-2",
    properties: dict[str, Any] | None = None,
    ingress_rules: tuple[NetworkIngressRule, ...] = (),
) -> Resource:
    return Resource(
        provider=provider,
        account_id=ACCOUNTS[provider],
        region=region,
        resource_type=resource_type,
        resource_id=f"{resource_type}/{name}",
        name=name,
        properties=properties or {},
        ingress_rules=ingress_rules,
        source_operation="test:Describe",
        collected_at=NOW,
    )


def security_group(name: str, *rules: NetworkIngressRule, region: str = "eu-west-2") -> Resource:
    return resource(
        Provider.AWS, "aws.ec2.security_group", name, region=region, ingress_rules=rules
    )


def nsg(name: str, *rules: NetworkIngressRule) -> Resource:
    return resource(Provider.AZURE, "azure.network.nsg", name, ingress_rules=rules)


def trail(name: str, *, multi_region: bool, logging: bool) -> Resource:
    return resource(
        Provider.AWS,
        "aws.cloudtrail.trail",
        name,
        properties={"is_multi_region": multi_region, "is_logging": logging},
    )


def storage_account(
    name: str,
    allow_public: bool | None,
    *,
    https_only: bool | None = True,
    minimum_tls_version: str | None = "TLS1_2",
) -> Resource:
    return resource(
        Provider.AZURE,
        "azure.storage.account",
        name,
        properties={
            "allow_blob_public_access": allow_public,
            "https_only": https_only,
            "minimum_tls_version": minimum_tls_version,
        },
    )


def inventory(
    provider: Provider, *resources: Resource, gaps: tuple[CollectionGap, ...] = ()
) -> Inventory:
    return Inventory(
        provider=provider,
        account_id=ACCOUNTS[provider],
        regions=("eu-west-2",),
        collected_at=NOW,
        resources=resources,
        gaps=gaps,
    )
