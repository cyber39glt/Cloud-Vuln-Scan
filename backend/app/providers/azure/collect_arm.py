"""Azure collection through ArmReader (plain, guarded ARM GETs) for resource types
where a full SDK package would add size without benefit.

API calls (all GET, all on the guard's allowlist), with the permission each needs:
  .../providers/Microsoft.Sql/servers
      Microsoft.Sql/servers/read
  {server}/firewallRules
      Microsoft.Sql/servers/firewallRules/read
  /subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettings
      Microsoft.Insights/diagnosticSettings/read
  /subscriptions/{id}/providers/Microsoft.Security/pricings
      Microsoft.Security/pricings/read
"""

from datetime import datetime
from typing import Any

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Resource
from app.providers.azure.arm import ArmReader
from app.providers.azure.errors import describe_azure_error
from app.providers.common import ReadOnlyViolation

SQL_SERVER = "azure.sql.server"
ACTIVITY_LOG = "azure.monitor.activity_log_export"
DEFENDER = "azure.security.defender_plans"

SQL_API = "2021-11-01"
DIAGNOSTICS_API = "2021-05-01-preview"
PRICINGS_API = "2024-01-01"

Collected = tuple[list[Resource], list[CollectionGap]]


def _gap(resource_type: str, error: Exception, prefix: str = "") -> CollectionGap:
    return CollectionGap(
        resource_type=resource_type, reason=prefix + describe_azure_error(error).code
    )


def _account_resource(
    subscription_id: str,
    resource_type: str,
    resource_id: str,
    name: str,
    properties: dict[str, Any],
    operation: str,
    collected_at: datetime,
) -> Resource:
    return Resource(
        provider=Provider.AZURE,
        account_id=subscription_id,
        region="global",
        resource_type=resource_type,
        resource_id=resource_id,
        name=name,
        properties=properties,
        source_operation=operation,
        collected_at=collected_at,
    )


def collect_sql_servers(arm: ArmReader, subscription_id: str, collected_at: datetime) -> Collected:
    try:
        servers = arm.list(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers", SQL_API
        )
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        return [], [_gap(SQL_SERVER, exc)]

    resources, gaps = [], []
    for server in servers:
        try:
            rules = arm.list(f"{server['id']}/firewallRules", SQL_API)
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            gaps.append(_gap(SQL_SERVER, exc, prefix=f"server {server.get('name')}: "))
            continue
        properties = server.get("properties", {})
        resources.append(
            Resource(
                provider=Provider.AZURE,
                account_id=subscription_id,
                region=(server.get("location") or "unknown").lower(),
                resource_type=SQL_SERVER,
                resource_id=server["id"],
                name=server.get("name") or server["id"],
                tags=dict(server.get("tags") or {}),
                properties={
                    "public_network_access": properties.get("publicNetworkAccess"),
                    "firewall_rules": [
                        {
                            "name": rule.get("name"),
                            "start_ip": rule.get("properties", {}).get("startIpAddress"),
                            "end_ip": rule.get("properties", {}).get("endIpAddress"),
                        }
                        for rule in rules
                    ],
                },
                source_operation=(
                    "Microsoft.Sql/servers/read, Microsoft.Sql/servers/firewallRules/read"
                ),
                collected_at=collected_at,
            )
        )
    return resources, gaps


def collect_activity_log_export(
    arm: ArmReader, subscription_id: str, collected_at: datetime
) -> Collected:
    path = f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/diagnosticSettings"
    try:
        settings = arm.list(path, DIAGNOSTICS_API)
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        return [], [_gap(ACTIVITY_LOG, exc)]
    summary = []
    for setting in settings:
        properties = setting.get("properties", {})
        summary.append(
            {
                "name": setting.get("name"),
                "has_destination": any(
                    properties.get(key)
                    for key in ("workspaceId", "storageAccountId", "eventHubAuthorizationRuleId")
                ),
                "enabled_categories": sorted(
                    log.get("category") or log.get("categoryGroup") or "?"
                    for log in properties.get("logs", [])
                    if log.get("enabled")
                ),
            }
        )
    return [
        _account_resource(
            subscription_id,
            ACTIVITY_LOG,
            path,
            "Activity Log diagnostic settings",
            {"settings": summary},
            "Microsoft.Insights/diagnosticSettings/read",
            collected_at,
        )
    ], []


def collect_defender_plans(
    arm: ArmReader, subscription_id: str, collected_at: datetime
) -> Collected:
    path = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings"
    try:
        pricings = arm.list(path, PRICINGS_API)
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        return [], [_gap(DEFENDER, exc)]
    plans = {
        p.get("name"): p.get("properties", {}).get("pricingTier") for p in pricings if p.get("name")
    }
    return [
        _account_resource(
            subscription_id,
            DEFENDER,
            path,
            "Microsoft Defender for Cloud plans",
            {"plans": dict(sorted(plans.items()))},
            "Microsoft.Security/pricings/read",
            collected_at,
        )
    ], []
