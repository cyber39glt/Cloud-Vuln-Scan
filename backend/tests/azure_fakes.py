"""Shared test doubles for Azure: no real tokens, tenants or network."""

import re
import time

from azure.core.credentials import AccessToken, AccessTokenInfo

TENANT = "22222222-2222-2222-2222-222222222222"
SUB = "11111111-1111-1111-1111-111111111111"
ARM = "https://management.azure.com"


class FakeCredential:
    """Stands in for an Entra ID token; nothing leaves the test process."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    def get_token(self, *_, **__):
        if self.error:
            raise self.error
        return AccessToken("fake-token", int(time.time()) + 3600)

    def get_token_info(self, *_, **__):
        if self.error:
            raise self.error
        return AccessTokenInfo("fake-token", int(time.time()) + 3600)


def arm_url(path: str) -> re.Pattern[str]:
    """Match an ARM URL for `path`, with any query string (api-version etc.)."""
    return re.compile(re.escape(f"{ARM}{path}") + r"\?.*")


def mock_subscription(rsps, tenant: str | None = TENANT, state: str | None = "Enabled") -> None:
    body = {"subscriptionId": SUB, "displayName": "Sandbox"}
    if tenant is not None:
        body["tenantId"] = tenant
    if state is not None:
        body["state"] = state
    rsps.get(arm_url(f"/subscriptions/{SUB}"), json=body)


def sql_server(name: str, public_network_access: str = "Enabled") -> dict:
    return {
        "id": f"/subscriptions/{SUB}/resourceGroups/demo-rg/providers/Microsoft.Sql/servers/{name}",
        "name": name,
        "location": "uksouth",
        "properties": {"publicNetworkAccess": public_network_access},
    }


def firewall_rule(name: str, start: str, end: str) -> dict:
    return {"name": name, "properties": {"startIpAddress": start, "endIpAddress": end}}


EXPORTED_ACTIVITY_LOG = {
    "name": "to-workspace",
    "properties": {
        "workspaceId": "/subscriptions/x/resourceGroups/y/providers/"
        "Microsoft.OperationalInsights/workspaces/z",
        "logs": [
            {"category": "Administrative", "enabled": True},
            {"category": "Security", "enabled": True},
        ],
    },
}

KEY_DEFENDER_PLANS = ("VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults")


def pricing(name: str, tier: str = "Standard") -> dict:
    return {"name": name, "properties": {"pricingTier": tier}}


def mock_arm_lists(
    rsps,
    sql_servers: dict[str, list[dict]] | None = None,
    diagnostic_settings: list[dict] | None = None,
    pricings: list[dict] | None = None,
) -> None:
    """The ArmReader lists. Defaults describe a well-configured subscription: no SQL
    servers, Activity Log exported, key Defender plans on Standard."""
    sql_servers = sql_servers or {}
    providers = f"/subscriptions/{SUB}/providers"
    rsps.get(
        arm_url(f"{providers}/Microsoft.Sql/servers"),
        json={"value": [sql_server(name) for name in sql_servers]},
    )
    for name, rules in sql_servers.items():
        server_id = sql_server(name)["id"]
        rsps.get(arm_url(f"{server_id}/firewallRules"), json={"value": rules})
    rsps.get(
        arm_url(f"{providers}/Microsoft.Insights/diagnosticSettings"),
        json={
            "value": [EXPORTED_ACTIVITY_LOG] if diagnostic_settings is None else diagnostic_settings
        },
    )
    rsps.get(
        arm_url(f"{providers}/Microsoft.Security/pricings"),
        json={"value": [pricing(p) for p in KEY_DEFENDER_PLANS] if pricings is None else pricings},
    )
