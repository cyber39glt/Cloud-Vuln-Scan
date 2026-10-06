"""Behaviour of each security rule, on minimal hand-built inventories."""

import pytest

from app.domain.enums import CheckStatus, Provider
from app.rules.aws.log_001_cloudtrail_multi_region import CloudTrailMultiRegionLogging
from app.rules.azure.sto_001_blob_public_access import StorageAccountAllowsPublicBlobAccess
from app.rules.common.net_001_management_ports_open import ManagementPortsOpenToInternet
from tests.factories import ingress, inventory, nsg, security_group, storage_account, trail


def statuses(rule, inv):
    return {r.resource_name: r.status for r in rule.evaluate(inv)}


# ------------------------------------------------------------------ NET-001
net = ManagementPortsOpenToInternet()


@pytest.mark.parametrize(
    "rule",
    [
        ingress(port=22, source="0.0.0.0/0"),
        ingress(port=3389, source="::/0"),
        ingress(port=(0, 65535), source="0.0.0.0/0"),
        ingress(port=(0, 65535), protocol="all", source="0.0.0.0/0"),
        ingress(port=(20, 25), source="0.0.0.0/0"),
    ],
)
def test_net_001_fails_for_internet_exposed_management_ports(rule):
    assert statuses(net, inventory(Provider.AWS, security_group("sg", rule))) == {
        "sg": CheckStatus.FAIL
    }


@pytest.mark.parametrize(
    "rule",
    [
        ingress(port=22, source="10.0.0.0/8"),  # private range
        ingress(port=443, source="0.0.0.0/0"),  # not a management port
        ingress(port=22, protocol="udp", source="0.0.0.0/0"),  # SSH is TCP
        ingress(port=(23, 3388), source="0.0.0.0/0"),  # range excludes both
    ],
)
def test_net_001_passes_when_not_exposed(rule):
    assert statuses(net, inventory(Provider.AWS, security_group("sg", rule))) == {
        "sg": CheckStatus.PASS
    }


def test_net_001_same_rule_works_for_azure_nsgs():
    inv = inventory(
        Provider.AZURE,
        nsg("open", ingress(port=3389, source="Internet", priority=300)),
        nsg("closed", ingress(port=3389, source="Internet", action="deny", priority=100)),
    )
    assert statuses(net, inv) == {"open": CheckStatus.FAIL, "closed": CheckStatus.PASS}


def test_net_001_reports_both_services_with_evidence():
    sg = security_group("sg", ingress(port=22), ingress(port=3389), ingress(port=443))
    [result] = net.evaluate(inventory(Provider.AWS, sg))

    assert result.message == "RDP and SSH open to the internet."
    [evidence] = result.evidence
    assert evidence.source_operation == "test:Describe"
    ports = [r["port_from"] for r in evidence.observed["inbound_rules"]]
    assert ports == [22, 3389]  # only the offending rules, not port 443


def test_net_001_rule_covering_both_ports_listed_once():
    sg = security_group("sg", ingress(port=(0, 65535)))
    [result] = net.evaluate(inventory(Provider.AWS, sg))
    assert len(result.evidence[0].observed["inbound_rules"]) == 1


# ------------------------------------------------------------------ AWS-LOG-001
cloudtrail = CloudTrailMultiRegionLogging()


@pytest.mark.parametrize(
    "trails",
    [
        [],
        [trail("t", multi_region=False, logging=True)],
        [trail("t", multi_region=True, logging=False)],
        [
            trail("a", multi_region=False, logging=True),
            trail("b", multi_region=True, logging=False),
        ],
    ],
)
def test_aws_log_001_fails_without_a_logging_multi_region_trail(trails):
    [result] = cloudtrail.evaluate(inventory(Provider.AWS, *trails))

    assert result.status == CheckStatus.FAIL
    assert result.resource_id is None  # account-level finding
    assert len(result.evidence[0].observed["trails"]) == len(trails)


def test_aws_log_001_passes_with_one_good_trail_among_others():
    inv = inventory(
        Provider.AWS,
        trail("regional", multi_region=False, logging=True),
        trail("org-trail", multi_region=True, logging=True),
    )
    [result] = cloudtrail.evaluate(inv)
    assert result.status == CheckStatus.PASS
    assert "org-trail" in result.message


# ------------------------------------------------------------------ AZ-STO-001
storage = StorageAccountAllowsPublicBlobAccess()


def test_az_sto_001_treats_unset_as_enabled():
    inv = inventory(
        Provider.AZURE,
        storage_account("enabled", True),
        storage_account("unset", None),
        storage_account("disabled", False),
    )
    assert statuses(storage, inv) == {
        "enabled": CheckStatus.FAIL,
        "unset": CheckStatus.FAIL,
        "disabled": CheckStatus.PASS,
    }


def test_failed_check_requires_evidence():
    with pytest.raises(ValueError, match="evidence"):
        storage.failed(storage_account("s", True), "no proof", [])
