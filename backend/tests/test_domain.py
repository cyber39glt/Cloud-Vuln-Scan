from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.core.logging import REDACTED
from app.domain.enums import Provider, Severity
from app.domain.findings import Evidence, finding_fingerprint
from app.domain.inventory import Inventory, Resource
from tests.factories import ACCOUNTS, NOW, ingress, security_group, storage_account


@pytest.mark.parametrize("source", ["0.0.0.0/0", "::/0", "*", "Internet", " ANY "])
def test_internet_sources_are_recognized(source):
    assert ingress(source=source).is_from_internet


@pytest.mark.parametrize("source", ["10.0.0.0/8", "203.0.113.5/32", "VirtualNetwork"])
def test_restricted_sources_are_not_internet(source):
    assert not ingress(source=source).is_from_internet


def test_port_ranges_and_protocols():
    wide = ingress(port=(0, 65535), protocol="tcp")
    everything = ingress(port=(0, 65535), protocol="all")
    udp_only = ingress(port=22, protocol="udp")

    assert wide.covers_port(22)
    assert everything.covers_port(3389)
    assert not udp_only.covers_port(22)  # SSH is TCP
    assert not ingress(port=(23, 3388)).covers_port(22)


def test_rejects_inverted_port_range():
    with pytest.raises(ValidationError, match="port_to"):
        ingress(port=(100, 10))


def test_rejects_invalid_resource_type():
    with pytest.raises(ValidationError, match="resource_type"):
        Resource.model_validate(security_group("x").model_dump() | {"resource_type": "bad type"})


def test_inventory_rejects_resources_from_another_account():
    """Client separation: one inventory can never mix accounts."""
    with pytest.raises(ValidationError, match="does not belong"):
        Inventory(
            provider=Provider.AZURE,
            account_id=ACCOUNTS[Provider.AZURE],
            regions=("uksouth",),
            collected_at=NOW,
            resources=(security_group("aws-sg"),),
        )


def test_models_are_immutable():
    sg = security_group("web")
    with pytest.raises(ValidationError):
        sg.name = "changed"


def test_inventory_filters_by_type():
    inv = Inventory(
        provider=Provider.AWS,
        account_id=ACCOUNTS[Provider.AWS],
        regions=("eu-west-2",),
        collected_at=NOW,
        resources=(security_group("a"), security_group("b")),
    )
    assert [r.name for r in inv.of_type("aws.ec2.security_group")] == ["a", "b"]
    assert inv.of_type("aws.cloudtrail.trail") == []


def test_evidence_redacts_secrets():
    evidence = Evidence(
        source_operation="test:Describe",
        collected_at=datetime.now(UTC),
        summary="found key AKIAIOSFODNN7EXAMPLE in user data",
        observed={"password": "hunter2", "port": 22},
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in evidence.summary
    assert evidence.observed == {"password": REDACTED, "port": 22}


def test_fingerprint_is_stable_and_specific():
    a = finding_fingerprint("NET-001", Provider.AWS, "111122223333", "sg-1")
    assert a == finding_fingerprint("NET-001", Provider.AWS, "111122223333", "sg-1")
    assert a != finding_fingerprint("NET-001", Provider.AWS, "111122223333", "sg-2")
    assert a != finding_fingerprint("NET-001", Provider.AWS, "444455556666", "sg-1")
    assert len(a) == 24


def test_severity_ordering():
    ranked = sorted(Severity, key=lambda s: s.rank, reverse=True)
    assert ranked == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    ]


def test_unknown_property_keys_are_kept_but_unknown_fields_rejected():
    assert storage_account("s", None).properties["allow_blob_public_access"] is None
    with pytest.raises(ValidationError):
        Inventory(
            provider=Provider.AWS,
            account_id="1",
            regions=(),
            collected_at=NOW,
            unexpected_field=True,
        )
