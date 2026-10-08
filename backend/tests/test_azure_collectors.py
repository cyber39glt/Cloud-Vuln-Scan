"""Azure collection and end-to-end scans, with Azure's REST API simulated by `responses`.

The JSON bodies below have the same shape Azure Resource Manager returns, so the
real Azure SDK code parses them exactly as it would in production.
"""

from datetime import UTC, datetime

import pytest
import responses
from azure.mgmt.network.models import SecurityRule

from app.cli import main as cli_main
from app.domain.enums import CheckStatus
from app.providers.azure.arm import ArmReader
from app.providers.azure.collect_arm import ACTIVITY_LOG, DEFENDER, collect_sql_servers
from app.providers.azure.collectors import (
    NSG,
    STORAGE_ACCOUNT,
    collect_inventory,
    normalize_security_rule,
)
from app.providers.azure.session import AzureConnection
from app.providers.common import ReadOnlyViolation
from app.scanning import WrongAccountError, scan_azure
from tests.azure_fakes import (
    EXPORTED_ACTIVITY_LOG,
    SUB,
    TENANT,
    FakeCredential,
    arm_url,
    firewall_rule,
    mock_arm_lists,
    mock_subscription,
    pricing,
    sql_server,
)

NOW = datetime(2026, 1, 15, tzinfo=UTC)
CONNECTION = AzureConnection(TENANT, SUB)
RG = f"/subscriptions/{SUB}/resourceGroups/demo-rg/providers"


def _rule(name: str, **properties) -> dict:
    defaults = {
        "protocol": "Tcp",
        "sourcePortRange": "*",
        "destinationAddressPrefix": "*",
        "access": "Allow",
        "direction": "Inbound",
        "priority": 100,
    }
    return {"name": name, "properties": defaults | properties}


def _nsg(name: str, location: str, *rules: dict) -> dict:
    return {
        "id": f"{RG}/Microsoft.Network/networkSecurityGroups/{name}",
        "name": name,
        "location": location,
        "tags": {"env": "test"},
        "properties": {"securityRules": list(rules)},
    }


def _exposed(name: str, source: str, port: str, access: str = "Allow") -> dict:
    """An NSG in uksouth with one inbound rule."""
    rule = _rule("r", sourceAddressPrefix=source, destinationPortRange=port, access=access)
    return _nsg(name, "uksouth", rule)


def _storage(name: str, location: str, public: bool | None) -> dict:
    properties = {"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2"}
    if public is not None:
        properties["allowBlobPublicAccess"] = public
    return {
        "id": f"{RG}/Microsoft.Storage/storageAccounts/{name}",
        "name": name,
        "location": location,
        "kind": "StorageV2",
        "properties": properties,
    }


def _mock_lists(rsps, nsgs=(), accounts=(), nsg_status=200, **arm_lists):
    nsg_body = (
        {"value": list(nsgs)}
        if nsg_status == 200
        else {"error": {"code": "AuthorizationFailed", "message": "no"}}
    )
    rsps.get(
        arm_url(f"/subscriptions/{SUB}/providers/Microsoft.Network/networkSecurityGroups"),
        json=nsg_body,
        status=nsg_status,
    )
    rsps.get(
        arm_url(f"/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts"),
        json={"value": list(accounts)},
    )
    mock_arm_lists(rsps, **arm_lists)


# ------------------------------------------------------------------ normalization


def _security_rule(**properties) -> SecurityRule:
    return SecurityRule(_rule("r", **properties))


@pytest.mark.parametrize(
    "properties, expected",
    [
        (
            {"sourceAddressPrefix": "*", "destinationPortRange": "22"},
            [("tcp", 22, 22, "*", "allow")],
        ),
        (
            {"sourceAddressPrefix": "Internet", "destinationPortRange": "3000-3400"},
            [("tcp", 3000, 3400, "Internet", "allow")],
        ),
        (  # multiple sources x multiple port ranges
            {
                "protocol": "*",
                "sourceAddressPrefixes": ["10.0.0.0/8", "0.0.0.0/0"],
                "destinationPortRanges": ["22", "3389"],
            },
            [
                ("all", 22, 22, "10.0.0.0/8", "allow"),
                ("all", 3389, 3389, "10.0.0.0/8", "allow"),
                ("all", 22, 22, "0.0.0.0/0", "allow"),
                ("all", 3389, 3389, "0.0.0.0/0", "allow"),
            ],
        ),
        (
            {"sourceAddressPrefix": "*", "destinationPortRange": "*", "access": "Deny"},
            [("tcp", 0, 65535, "*", "deny")],
        ),
        ({"direction": "Outbound", "sourceAddressPrefix": "*", "destinationPortRange": "22"}, []),
        ({"protocol": "Esp", "sourceAddressPrefix": "*", "destinationPortRange": "*"}, []),
    ],
)
def test_normalize_security_rule(properties, expected):
    rules = normalize_security_rule(_security_rule(**properties))
    assert [(r.protocol, r.port_from, r.port_to, r.source, r.action) for r in rules] == expected


def test_application_security_groups_are_not_internet_sources():
    rule = _security_rule(
        destinationPortRange="22",
        sourceApplicationSecurityGroups=[{"id": f"{RG}/Microsoft.Network/asgs/web"}],
    )
    [normalized] = normalize_security_rule(rule)
    assert not normalized.is_from_internet


# ------------------------------------------------------------------ collection


def test_collects_nsgs_and_storage_accounts():
    with responses.RequestsMock() as rsps:
        _mock_lists(
            rsps,
            nsgs=[_exposed("jumpbox-nsg", "*", "22") | {"location": "UKSouth"}],
            accounts=[_storage("publicdata", "uksouth", None)],
        )
        inventory = collect_inventory(FakeCredential(), SUB.upper(), clock=lambda: NOW)

    [nsg] = inventory.of_type(NSG)
    assert (nsg.name, nsg.region, nsg.account_id) == ("jumpbox-nsg", "uksouth", SUB)
    assert nsg.properties == {"resource_group": "demo-rg"}
    assert nsg.ingress_rules[0].port_from == 22
    [account] = inventory.of_type(STORAGE_ACCOUNT)
    assert account.properties["allow_blob_public_access"] is None  # never set
    assert inventory.regions == ("uksouth",)
    assert inventory.gaps == ()


def test_region_scope_discards_other_locations():
    with responses.RequestsMock() as rsps:
        _mock_lists(
            rsps,
            nsgs=[_nsg("uk", "uksouth"), _nsg("us", "eastus")],
            accounts=[_storage("usdata", "eastus", True)],
        )
        inventory = collect_inventory(FakeCredential(), SUB, regions=["UKSouth"])

    assert [r.name for r in inventory.resources if r.region != "global"] == ["uk"]
    assert inventory.regions == ("uksouth",)


def test_access_denied_becomes_a_gap_and_other_types_still_collected():
    with responses.RequestsMock() as rsps:
        _mock_lists(rsps, accounts=[_storage("a", "uksouth", False)], nsg_status=403)
        inventory = collect_inventory(FakeCredential(), SUB)

    [gap] = inventory.gaps
    assert (gap.resource_type, gap.reason) == (NSG, "AuthorizationFailed")
    assert [r.name for r in inventory.of_type(STORAGE_ACCOUNT)] == ["a"]


def test_read_only_violation_is_never_swallowed(monkeypatch):
    from app.providers.azure import collectors

    def broken(*_args, **_kwargs):
        raise ReadOnlyViolation("Blocked by read-only guard: POST is not allowed.")

    monkeypatch.setattr(collectors, "normalize_nsg", broken)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _mock_lists(rsps, nsgs=[_nsg("x", "uksouth")])
        with pytest.raises(ReadOnlyViolation):
            collect_inventory(FakeCredential(), SUB)


# ------------------------------------------------------------------ end-to-end scans


def _planted_weaknesses(rsps):
    mock_subscription(rsps)
    _mock_lists(
        rsps,
        nsgs=[
            _exposed("ssh-open", "Internet", "22"),
            _exposed("rdp-open", "*", "3389"),
            _exposed("rdp-denied", "*", "3389", access="Deny"),
            _exposed("internal", "10.0.0.0/8", "22"),
        ],
        accounts=[
            _storage("unsetpublic", "uksouth", None),
            _storage("privatedata", "uksouth", False),
        ],
        sql_servers={
            "open-sql": [
                firewall_rule("AllowAll", "0.0.0.0", "255.255.255.255"),
                firewall_rule("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0"),
            ],
            "private-sql": [firewall_rule("office", "203.0.113.10", "203.0.113.10")],
        },
    )


def test_full_scan_finds_the_planted_weaknesses(settings):
    with responses.RequestsMock() as rsps:
        _planted_weaknesses(rsps)
        result = scan_azure(CONNECTION, settings, credential=FakeCredential())

    found = {(f.rule_id, f.resource_name) for f in result.findings}
    assert found == {
        ("NET-001", "ssh-open"),
        ("NET-002", "rdp-open"),
        ("AZ-STO-001", "unsetpublic"),
        ("AZ-EXP-001", "open-sql"),
        ("AZ-EXP-002", "open-sql"),
    }
    [rdp] = [f for f in result.findings if f.rule_id == "NET-002"]
    cis = [r.control_id for r in rdp.framework_refs if r.framework.value == "cis_azure"]
    assert cis == ["6.1"]
    assert result.provider.value == "azure" and result.account_id == SUB


@pytest.mark.parametrize(
    "tenant, state",
    [("99999999-9999-9999-9999-999999999999", "Enabled"), (None, "Enabled"), (TENANT, "Disabled")],
)
def test_scan_stops_before_collecting_for_unexpected_subscriptions(settings, tenant, state):
    with responses.RequestsMock() as rsps:
        mock_subscription(rsps, tenant=tenant, state=state)
        with pytest.raises(WrongAccountError):
            scan_azure(CONNECTION, settings, credential=FakeCredential())
        assert len(rsps.calls) == 1  # only the subscription check; nothing collected


def test_scan_reports_not_evaluated_when_nsgs_cannot_be_read(settings):
    with responses.RequestsMock() as rsps:
        mock_subscription(rsps)
        _mock_lists(rsps, nsg_status=403)
        result = scan_azure(CONNECTION, settings, credential=FakeCredential())

    net = [r for r in result.results if r.rule_id in ("NET-001", "NET-002")]
    assert {r.status for r in net} == {CheckStatus.ERROR}
    assert not [f for f in result.findings if f.rule_id.startswith("NET")]


def test_cli_azure_scan_unsaved(settings, capsys, monkeypatch):
    from app import cli

    monkeypatch.setattr(cli, "scan_azure", lambda c, s, regions=None: _scan_with_fakes(c, s))
    code = cli_main(["azure", "scan", "--tenant-id", TENANT, "--subscription-id", SUB])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "Read-only." in out
    assert "[HIGH] NET-001 SSH open to the internet" in out
    assert "Not saved" in out


def _scan_with_fakes(connection, settings):
    with responses.RequestsMock() as rsps:
        _planted_weaknesses(rsps)
        return scan_azure(connection, settings, credential=FakeCredential())


def test_sandbox_fixture_template_produces_the_documented_findings():
    """infra/azure/sandbox-test-fixtures.json documents what a scan should find. Run its
    NSG and storage definitions through the real normalizers and rules to prove it."""
    import json
    from pathlib import Path

    from azure.mgmt.network.models import NetworkSecurityGroup
    from azure.mgmt.storage.models import StorageAccount

    from app.domain.enums import Provider
    from app.domain.inventory import Inventory
    from app.providers.azure.collectors import normalize_nsg, normalize_storage_account
    from app.rules.engine import RuleEngine

    template_path = Path(__file__).parents[2] / "infra" / "azure" / "sandbox-test-fixtures.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))
    resources = []
    for item in template["resources"]:
        name = "cvstest-storage" if item["name"].startswith("[") else item["name"]
        kind = item["type"].split("/")[-1]
        raw = {
            "id": f"{RG}/{item['type']}/{name}",
            "name": name,
            "location": "uksouth",
            "properties": item["properties"],
        }
        if kind == "networkSecurityGroups":
            resources.append(normalize_nsg(NetworkSecurityGroup(raw), SUB, NOW))
        else:
            resources.append(normalize_storage_account(StorageAccount(raw), SUB, NOW))

    inventory = Inventory(
        provider=Provider.AZURE,
        account_id=SUB,
        regions=("uksouth",),
        collected_at=NOW,
        resources=tuple(resources),
    )
    found = sorted((f.rule_id, f.resource_name) for f in RuleEngine().run(inventory).findings)
    assert found == [
        ("AZ-STO-001", "cvstest-storage"),
        ("NET-001", "cvs-test-all-open"),
        ("NET-001", "cvs-test-ssh-open"),
        ("NET-002", "cvs-test-all-open"),
        ("NET-002", "cvs-test-rdp-open"),
    ]


# ------------------------------------------------------------------ ARM lists (SQL, logs, Defender)


def test_sql_servers_follow_next_link_pages_and_keep_only_firewall_ranges():
    providers = f"/subscriptions/{SUB}/providers"
    first, second = sql_server("sql-a"), sql_server("sql-b", "Disabled")
    next_link = f"https://management.azure.com{providers}/Microsoft.Sql/servers?page=2"
    with responses.RequestsMock() as rsps:
        rsps.get(
            arm_url(f"{providers}/Microsoft.Sql/servers"),
            json={"value": [first], "nextLink": next_link},
        )
        rsps.get(next_link, json={"value": [second]})
        rsps.get(
            arm_url(f"{first['id']}/firewallRules"),
            json={"value": [firewall_rule("office", "203.0.113.10", "203.0.113.20")]},
        )
        rsps.get(arm_url(f"{second['id']}/firewallRules"), json={"value": []})
        resources, gaps = collect_sql_servers(ArmReader(FakeCredential()), SUB, NOW)

    assert gaps == []
    servers = {r.name: r.properties for r in resources}
    assert servers["sql-a"] == {
        "public_network_access": "Enabled",
        "firewall_rules": [
            {"name": "office", "start_ip": "203.0.113.10", "end_ip": "203.0.113.20"}
        ],
    }
    assert servers["sql-b"]["public_network_access"] == "Disabled"


def test_next_link_to_another_host_is_blocked_by_the_guard():
    providers = f"/subscriptions/{SUB}/providers"
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.get(
            arm_url(f"{providers}/Microsoft.Sql/servers"),
            json={"value": [], "nextLink": "https://attacker.example/steal"},
        )
        with pytest.raises(ReadOnlyViolation):
            collect_sql_servers(ArmReader(FakeCredential()), SUB, NOW)
        assert len(rsps.calls) == 1  # the redirect target was never contacted


def test_unreadable_firewall_rules_are_a_gap_for_that_server_only():
    providers = f"/subscriptions/{SUB}/providers"
    denied, readable = sql_server("denied"), sql_server("readable")
    with responses.RequestsMock() as rsps:
        rsps.get(arm_url(f"{providers}/Microsoft.Sql/servers"), json={"value": [denied, readable]})
        rsps.get(
            arm_url(f"{denied['id']}/firewallRules"),
            json={"error": {"code": "AuthorizationFailed", "message": "no"}},
            status=403,
        )
        rsps.get(arm_url(f"{readable['id']}/firewallRules"), json={"value": []})
        resources, gaps = collect_sql_servers(ArmReader(FakeCredential()), SUB, NOW)

    assert [r.name for r in resources] == ["readable"]
    [gap] = gaps
    assert gap.reason == "server denied: AuthorizationFailed"


def test_activity_log_settings_are_summarized_without_destination_ids():
    with responses.RequestsMock() as rsps:
        mock_arm_lists(
            rsps,
            diagnostic_settings=[
                EXPORTED_ACTIVITY_LOG,
                {
                    "name": "disabled",
                    "properties": {"logs": [{"category": "Administrative", "enabled": False}]},
                },
            ],
        )
        inventory = collect_inventory(FakeCredential(), SUB, regions=["uksouth"], clock=lambda: NOW)

    [export] = inventory.of_type(ACTIVITY_LOG)
    assert export.region == "global"  # subscription-wide: kept despite the region filter
    assert export.properties == {
        "settings": [
            {
                "name": "to-workspace",
                "has_destination": True,
                "enabled_categories": ["Administrative", "Security"],
            },
            {"name": "disabled", "has_destination": False, "enabled_categories": []},
        ]
    }
    [defender] = inventory.of_type(DEFENDER)
    assert set(defender.properties["plans"].values()) == {"Standard"}


@pytest.mark.parametrize(
    "failing", ["Microsoft.Insights/diagnosticSettings", "Microsoft.Security/pricings"]
)
def test_account_settings_access_denied_is_a_gap_and_rule_not_evaluated(settings, failing):
    providers = f"/subscriptions/{SUB}/providers"
    # The 403 is registered first, so it wins over the default mock for the same URL.
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        mock_subscription(rsps)
        rsps.get(
            arm_url(f"{providers}/{failing}"),
            json={"error": {"code": "AuthorizationFailed", "message": "no"}},
            status=403,
        )
        _mock_lists(rsps)
        result = scan_azure(CONNECTION, settings, credential=FakeCredential())

    rule_id = "AZ-LOG-001" if "Insights" in failing else "AZ-SEC-001"
    [check] = [r for r in result.results if r.rule_id == rule_id]
    assert check.status == CheckStatus.ERROR  # NOT a false "not exported / not enabled"
    assert not [f for f in result.findings if f.rule_id == rule_id]


def test_scan_reports_missing_activity_log_export_and_defender_plans(settings):
    with responses.RequestsMock() as rsps:
        mock_subscription(rsps)
        _mock_lists(rsps, diagnostic_settings=[], pricings=[pricing("VirtualMachines", "Free")])
        result = scan_azure(CONNECTION, settings, credential=FakeCredential())

    assert {"AZ-LOG-001", "AZ-SEC-001"} <= {f.rule_id for f in result.findings}
