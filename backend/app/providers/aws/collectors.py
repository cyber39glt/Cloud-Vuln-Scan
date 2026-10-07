"""AWS collectors: read configuration through the guarded session and translate it
into the normalized inventory the rules understand.

Principles:
- Read only what rules need (data minimization): e.g. a security group keeps its
  ID, VPC, name, tags and inbound rules; nothing else.
- Failures never look like "nothing found". A region or call that fails becomes a
  CollectionGap, which the engine reports as "not evaluated".
- A ReadOnlyViolation is a code bug, never a gap: it is re-raised immediately.

API calls made (all on the guard's allowlist):
  ec2:DescribeRegions, ec2:DescribeSecurityGroups,
  cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus
"""

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Inventory, NetworkIngressRule, Resource
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.guard import ReadOnlyViolation
from app.providers.aws.session import CLIENT_CONFIG

logger = logging.getLogger(__name__)

SECURITY_GROUP = "aws.ec2.security_group"
CLOUDTRAIL_TRAIL = "aws.cloudtrail.trail"

# AWS reports protocols as names or IANA numbers; "-1" means all traffic.
_PROTOCOLS = {"-1": "all", "tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp",
              "icmp": "icmp", "1": "icmp", "icmpv6": "icmp", "58": "icmp"}  # fmt: skip


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _gap_reason(error: Exception) -> str:
    return describe_aws_error(error).code


def _tags(raw_tags: Iterable[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in raw_tags or [] if "Key" in t}


# ------------------------------------------------------------------ security groups


def normalize_ingress(permission: dict[str, Any]) -> list[NetworkIngressRule]:
    """One AWS IpPermission -> one normalized rule per source.
    Protocols other than TCP/UDP/ICMP/all (e.g. ESP) are ignored: they cannot
    expose SSH or RDP-style services."""
    protocol = _PROTOCOLS.get(str(permission.get("IpProtocol", "")).lower())
    if protocol is None:
        return []
    if protocol in ("tcp", "udp"):
        port_from = permission.get("FromPort", 0)
        port_to = permission.get("ToPort", 65535)
        if port_from < 0 or port_to < 0:  # -1 = all ports
            port_from, port_to = 0, 65535
    else:
        port_from, port_to = 0, 65535

    sources: list[tuple[str, str | None]] = []
    sources += [(r["CidrIp"], r.get("Description")) for r in permission.get("IpRanges", [])]
    sources += [(r["CidrIpv6"], r.get("Description")) for r in permission.get("Ipv6Ranges", [])]
    sources += [
        (r["PrefixListId"], r.get("Description")) for r in permission.get("PrefixListIds", [])
    ]
    sources += [
        (r["GroupId"], r.get("Description"))
        for r in permission.get("UserIdGroupPairs", [])
        if "GroupId" in r
    ]
    return [
        NetworkIngressRule(
            protocol=protocol,
            port_from=port_from,
            port_to=port_to,
            source=source,
            rule_name=(description or None) and description[:256],
        )
        for source, description in sources
    ]


def normalize_security_group(
    raw: dict[str, Any], account_id: str, region: str, collected_at: datetime
) -> Resource:
    group_id = raw["GroupId"]
    return Resource(
        provider=Provider.AWS,
        account_id=account_id,
        region=region,
        resource_type=SECURITY_GROUP,
        resource_id=raw.get("SecurityGroupArn")
        or f"arn:aws:ec2:{region}:{account_id}:security-group/{group_id}",
        name=raw.get("GroupName", group_id),
        tags=_tags(raw.get("Tags")),
        properties={"group_id": group_id, "vpc_id": raw.get("VpcId")},
        ingress_rules=tuple(
            rule
            for permission in raw.get("IpPermissions", [])
            for rule in normalize_ingress(permission)
        ),
        source_operation="ec2:DescribeSecurityGroups",
        collected_at=collected_at,
    )


def collect_security_groups(
    session: Any, account_id: str, regions: list[str], collected_at: datetime
) -> tuple[list[Resource], list[CollectionGap]]:
    resources: list[Resource] = []
    gaps: list[CollectionGap] = []
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region, config=CLIENT_CONFIG)
            for page in ec2.get_paginator("describe_security_groups").paginate():
                resources += [
                    normalize_security_group(raw, account_id, region, collected_at)
                    for raw in page.get("SecurityGroups", [])
                ]
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            gaps.append(
                CollectionGap(resource_type=SECURITY_GROUP, region=region, reason=_gap_reason(exc))
            )
    return resources, gaps


# ------------------------------------------------------------------ CloudTrail


def collect_trails(
    session: Any, account_id: str, home_region: str, collected_at: datetime
) -> tuple[list[Resource], list[CollectionGap]]:
    """DescribeTrails with shadow trails returns every trail that applies to this
    account, including multi-region and organization trails created elsewhere."""
    try:
        cloudtrail = session.client("cloudtrail", region_name=home_region, config=CLIENT_CONFIG)
        raw_trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        return [], [CollectionGap(resource_type=CLOUDTRAIL_TRAIL, reason=_gap_reason(exc))]

    resources: list[Resource] = []
    gaps: list[CollectionGap] = []
    seen: set[str] = set()
    for trail in raw_trails:
        arn = trail["TrailARN"]
        if arn in seen:
            continue
        seen.add(arn)
        trail_region = trail.get("HomeRegion", home_region)
        try:
            status = session.client(
                "cloudtrail", region_name=trail_region, config=CLIENT_CONFIG
            ).get_trail_status(Name=arn)
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            # Without status we cannot say whether it logs: record a gap rather
            # than guess. (Typical for organization trails owned by another account.)
            gaps.append(
                CollectionGap(
                    resource_type=CLOUDTRAIL_TRAIL,
                    region=trail_region,
                    reason=f"status of trail {trail.get('Name', arn)} unavailable: "
                    f"{_gap_reason(exc)}",
                )
            )
            continue
        resources.append(
            Resource(
                provider=Provider.AWS,
                account_id=account_id,
                region=trail_region,
                resource_type=CLOUDTRAIL_TRAIL,
                resource_id=arn,
                name=trail.get("Name", arn),
                properties={
                    "is_multi_region": bool(trail.get("IsMultiRegionTrail")),
                    "is_logging": bool(status.get("IsLogging")),
                    "is_organization_trail": bool(trail.get("IsOrganizationTrail")),
                    "log_file_validation": bool(trail.get("LogFileValidationEnabled")),
                },
                source_operation="cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
                collected_at=collected_at,
            )
        )
    return resources, gaps


# ------------------------------------------------------------------ regions + inventory


def enabled_regions(session: Any, default_region: str) -> list[str]:
    """Regions enabled for this account (DescribeRegions omits opted-out regions)."""
    ec2 = session.client("ec2", region_name=default_region, config=CLIENT_CONFIG)
    return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])


def collect_inventory(
    session: Any,
    account_id: str,
    default_region: str,
    regions: list[str] | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> Inventory:
    """Collect everything the enabled AWS rules need from one account.

    `regions` limits the scope to what was agreed with the client; by default every
    enabled region is assessed. Requested regions that are not enabled are reported
    as gaps rather than silently skipped.
    """
    collected_at = clock()
    gaps: list[CollectionGap] = []

    try:
        available = enabled_regions(session, default_region)
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        reason = f"could not list regions: {_gap_reason(exc)}"
        available = [default_region]
        gaps.append(CollectionGap(resource_type=SECURITY_GROUP, reason=reason))

    if regions:
        scope = sorted(r for r in set(regions) if r in available)
        gaps += [
            CollectionGap(resource_type=SECURITY_GROUP, region=r, reason="region not enabled")
            for r in sorted(set(regions) - set(available))
        ]
    else:
        scope = available

    security_groups, sg_gaps = collect_security_groups(session, account_id, scope, collected_at)
    trails, trail_gaps = collect_trails(session, account_id, default_region, collected_at)

    inventory = Inventory(
        provider=Provider.AWS,
        account_id=account_id,
        regions=tuple(scope),
        collected_at=collected_at,
        resources=tuple(security_groups + trails),
        gaps=tuple(gaps + sg_gaps + trail_gaps),
    )
    logger.info(
        "aws inventory collected",
        extra={
            "account_id": account_id,
            "regions": len(scope),
            "resources": len(inventory.resources),
            "gaps": len(inventory.gaps),
        },
    )
    return inventory
