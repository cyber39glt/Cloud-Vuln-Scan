"""Azure collectors: read configuration through guarded SDK clients and translate it
into the normalized inventory the rules understand.

Same principles as the AWS collectors:
- Keep only what rules need (data minimization).
- A failed read becomes a CollectionGap ("not evaluated"), never "nothing found".
- A ReadOnlyViolation is a code bug and stops the scan.

API calls made (all GET, all on the guard's allowlist):
  GET .../providers/Microsoft.Network/networkSecurityGroups   (whole subscription)
  GET .../providers/Microsoft.Storage/storageAccounts         (whole subscription)
"""

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Inventory, NetworkIngressRule, Resource
from app.providers.azure.errors import describe_azure_error
from app.providers.azure.guard import guarded_client
from app.providers.common import ReadOnlyViolation

logger = logging.getLogger(__name__)

NSG = "azure.network.nsg"
STORAGE_ACCOUNT = "azure.storage.account"

_PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "*": "all"}  # Esp/Ah: not relevant


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _text(value: Any) -> str:
    """SDK enums (e.g. SecurityRuleProtocol.TCP) and plain strings -> plain string."""
    return str(getattr(value, "value", value) or "")


def _resource_group(resource_id: str) -> str | None:
    parts = resource_id.split("/")
    lowered = [p.lower() for p in parts]
    if "resourcegroups" in lowered:
        index = lowered.index("resourcegroups")
        return parts[index + 1] if index + 1 < len(parts) else None
    return None


def _port_ranges(single: str | None, many: Iterable[str] | None) -> list[tuple[int, int]]:
    """'22' -> (22, 22); '1000-2000' -> (1000, 2000); '*' -> (0, 65535)."""
    ranges = []
    for item in [single, *(many or [])]:
        text = (item or "").strip()
        if not text:
            continue
        if text == "*":
            ranges.append((0, 65535))
        elif "-" in text:
            low, high = text.split("-", 1)
            ranges.append((int(low), int(high)))
        else:
            ranges.append((int(text), int(text)))
    return ranges


# ------------------------------------------------------------------ NSGs


def normalize_security_rule(rule: Any) -> list[NetworkIngressRule]:
    """One Azure inbound security rule -> one normalized rule per source x port range.
    Outbound rules and protocols other than TCP/UDP/ICMP/any are ignored."""
    if _text(rule.direction).lower() != "inbound":
        return []
    protocol = _PROTOCOLS.get(_text(rule.protocol).lower())
    if protocol is None:
        return []
    sources = [s for s in [rule.source_address_prefix, *(rule.source_address_prefixes or [])] if s]
    # Application security groups are internal references, never "the internet".
    sources += [asg.id for asg in rule.source_application_security_groups or [] if asg.id]
    if protocol in ("icmp", "all") and not (
        rule.destination_port_range or rule.destination_port_ranges
    ):
        ports = [(0, 65535)]
    else:
        ports = _port_ranges(rule.destination_port_range, rule.destination_port_ranges)
    return [
        NetworkIngressRule(
            protocol=protocol,
            port_from=port_from,
            port_to=port_to,
            source=source,
            action="allow" if _text(rule.access).lower() == "allow" else "deny",
            priority=rule.priority,
            rule_name=(rule.name or None) and rule.name[:256],
        )
        for source in sources
        for port_from, port_to in ports
    ]


def normalize_nsg(raw: Any, subscription_id: str, collected_at: datetime) -> Resource:
    return Resource(
        provider=Provider.AZURE,
        account_id=subscription_id,
        region=(raw.location or "unknown").lower(),
        resource_type=NSG,
        resource_id=raw.id,
        name=raw.name or raw.id,
        tags=dict(raw.tags or {}),
        properties={"resource_group": _resource_group(raw.id)},
        # Custom rules only: Azure's built-in default rules never allow internet inbound.
        ingress_rules=tuple(
            normalized
            for rule in raw.security_rules or []
            for normalized in normalize_security_rule(rule)
        ),
        source_operation="Microsoft.Network/networkSecurityGroups/read",
        collected_at=collected_at,
    )


# ------------------------------------------------------------------ storage accounts


def normalize_storage_account(raw: Any, subscription_id: str, collected_at: datetime) -> Resource:
    return Resource(
        provider=Provider.AZURE,
        account_id=subscription_id,
        region=(raw.location or "unknown").lower(),
        resource_type=STORAGE_ACCOUNT,
        resource_id=raw.id,
        name=raw.name or raw.id,
        tags=dict(raw.tags or {}),
        properties={
            "resource_group": _resource_group(raw.id),
            # None means "never set", which Azure treats as allowed (see AZ-STO-001).
            "allow_blob_public_access": raw.allow_blob_public_access,
        },
        source_operation="Microsoft.Storage/storageAccounts/read",
        collected_at=collected_at,
    )


# ------------------------------------------------------------------ inventory


def _collect(
    resource_type: str,
    list_call: Callable[[], Iterable[Any]],
    normalize: Callable[[Any], Resource],
) -> tuple[list[Resource], list[CollectionGap]]:
    try:
        return [normalize(raw) for raw in list_call()], []
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        return [], [
            CollectionGap(resource_type=resource_type, reason=describe_azure_error(exc).code)
        ]


def collect_inventory(
    credential: Any,
    subscription_id: str,
    regions: list[str] | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> Inventory:
    """Collect everything the enabled Azure rules need from ONE subscription.

    Azure lists resources subscription-wide. `regions` limits the assessment to the
    locations agreed with the client; resources elsewhere are discarded, not kept.
    """
    collected_at = clock()
    subscription_id = subscription_id.lower()
    network = guarded_client(NetworkManagementClient, credential, subscription_id)
    storage = guarded_client(StorageManagementClient, credential, subscription_id)

    nsgs, nsg_gaps = _collect(
        NSG,
        network.network_security_groups.list_all,
        lambda raw: normalize_nsg(raw, subscription_id, collected_at),
    )
    accounts, storage_gaps = _collect(
        STORAGE_ACCOUNT,
        storage.storage_accounts.list,
        lambda raw: normalize_storage_account(raw, subscription_id, collected_at),
    )
    resources = nsgs + accounts
    if regions:
        wanted = {r.lower() for r in regions}
        resources = [r for r in resources if r.region in wanted]
        scope = sorted(wanted)
    else:
        scope = sorted({r.region for r in resources})

    inventory = Inventory(
        provider=Provider.AZURE,
        account_id=subscription_id,
        regions=tuple(scope),
        collected_at=collected_at,
        resources=tuple(resources),
        gaps=tuple(nsg_gaps + storage_gaps),
    )
    logger.info(
        "azure inventory collected",
        extra={
            "subscription_id": subscription_id,
            "resources": len(inventory.resources),
            "gaps": len(inventory.gaps),
        },
    )
    return inventory
