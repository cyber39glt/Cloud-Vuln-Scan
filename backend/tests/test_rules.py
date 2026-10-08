"""Behaviour of each security rule, on minimal hand-built inventories."""

import pytest

from app.domain.enums import CheckStatus, Provider
from app.rules.aws.log_001_cloudtrail_multi_region import CloudTrailMultiRegionLogging
from app.rules.azure.sto_001_blob_public_access import StorageAccountAllowsPublicBlobAccess
from app.rules.common.net_001_ssh_open_to_internet import SshOpenToInternet
from app.rules.common.net_002_rdp_open_to_internet import RdpOpenToInternet
from tests.factories import ingress, inventory, nsg, security_group, storage_account, trail


def statuses(rule, inv):
    return {r.resource_name: r.status for r in rule.evaluate(inv)}


# ------------------------------------------------------------------ NET-001 / NET-002
ssh = SshOpenToInternet()
rdp = RdpOpenToInternet()


@pytest.mark.parametrize(
    "rule, ingress_rule",
    [
        (ssh, ingress(port=22, source="0.0.0.0/0")),
        (ssh, ingress(port=(20, 25), source="0.0.0.0/0")),
        (ssh, ingress(port=(0, 65535), protocol="all", source="0.0.0.0/0")),
        (rdp, ingress(port=3389, source="::/0")),
        (rdp, ingress(port=(0, 65535), source="0.0.0.0/0")),
    ],
)
def test_fails_for_internet_exposed_port(rule, ingress_rule):
    assert statuses(rule, inventory(Provider.AWS, security_group("sg", ingress_rule))) == {
        "sg": CheckStatus.FAIL
    }


@pytest.mark.parametrize(
    "rule, ingress_rule",
    [
        (ssh, ingress(port=22, source="10.0.0.0/8")),  # private range
        (ssh, ingress(port=443, source="0.0.0.0/0")),  # not SSH
        (ssh, ingress(port=22, protocol="udp", source="0.0.0.0/0")),  # SSH is TCP
        (ssh, ingress(port=3389, source="0.0.0.0/0")),  # RDP is NET-002's job
        (rdp, ingress(port=22, source="0.0.0.0/0")),  # SSH is NET-001's job
        (rdp, ingress(port=(23, 3388), source="0.0.0.0/0")),  # range excludes 3389
    ],
)
def test_passes_when_port_not_exposed(rule, ingress_rule):
    assert statuses(rule, inventory(Provider.AWS, security_group("sg", ingress_rule))) == {
        "sg": CheckStatus.PASS
    }


def test_same_rule_works_for_azure_nsgs():
    inv = inventory(
        Provider.AZURE,
        nsg("open", ingress(port=3389, source="Internet", priority=300)),
        nsg("closed", ingress(port=3389, source="Internet", action="deny", priority=100)),
    )
    assert statuses(rdp, inv) == {"open": CheckStatus.FAIL, "closed": CheckStatus.PASS}


def test_each_service_reported_separately_with_only_its_evidence():
    inv = inventory(
        Provider.AWS,
        security_group("sg", ingress(port=22), ingress(port=3389), ingress(port=443)),
    )
    [ssh_result] = ssh.evaluate(inv)
    [rdp_result] = rdp.evaluate(inv)

    assert ssh_result.message == "SSH (TCP 22) open to the internet."
    assert rdp_result.message == "RDP (TCP 3389) open to the internet."
    assert [r["port_from"] for r in ssh_result.evidence[0].observed["inbound_rules"]] == [22]
    assert [r["port_from"] for r in rdp_result.evidence[0].observed["inbound_rules"]] == [3389]
    assert ssh_result.evidence[0].source_operation == "test:Describe"


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
