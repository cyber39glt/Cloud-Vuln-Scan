"""AWS collection and end-to-end scans against moto (simulated AWS).

Test setup creates misconfigured resources with a plain boto3 client, exactly as a
person would in a sandbox. The code under test only ever uses the guarded session.
"""

from datetime import UTC, datetime

import boto3
import pytest
from botocore.exceptions import ClientError

from app.cli import main as cli_main
from app.domain.enums import CheckStatus
from app.providers.aws.collectors import (
    CLOUDTRAIL_TRAIL,
    SECURITY_GROUP,
    collect_inventory,
    normalize_ingress,
    normalize_security_group,
)
from app.providers.aws.guard import ReadOnlyViolation
from app.providers.aws.session import AwsConnection, assume_assessment_role
from app.scanning import WrongAccountError, scan_aws

ACCOUNT = "123456789012"
NOW = datetime(2026, 1, 15, tzinfo=UTC)
CONNECTION = AwsConnection(ACCOUNT, "subtletech-test-external-id", "SubtleTechSecurityAssessment")


# ------------------------------------------------------------------ normalization (no AWS)


@pytest.mark.parametrize(
    "permission, expected",
    [
        (
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            [("tcp", 22, 22, "0.0.0.0/0")],
        ),
        (  # "-1" = all traffic: AWS omits ports
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
            [("all", 0, 65535, "10.0.0.0/8")],
        ),
        (  # protocol numbers, IPv6, prefix lists and security-group references
            {
                "IpProtocol": "6",
                "FromPort": 3389,
                "ToPort": 3389,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                "PrefixListIds": [{"PrefixListId": "pl-123"}],
                "UserIdGroupPairs": [{"GroupId": "sg-abc"}],
            },
            [
                ("tcp", 3389, 3389, "::/0"),
                ("tcp", 3389, 3389, "pl-123"),
                ("tcp", 3389, 3389, "sg-abc"),
            ],
        ),
        (  # ICMP "ports" are type/code, not ports
            {
                "IpProtocol": "icmp",
                "FromPort": 8,
                "ToPort": -1,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            [("icmp", 0, 65535, "0.0.0.0/0")],
        ),
        ({"IpProtocol": "50", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, []),  # ESP: ignored
    ],
)
def test_normalize_ingress(permission, expected):
    rules = normalize_ingress(permission)
    assert [(r.protocol, r.port_from, r.port_to, r.source) for r in rules] == expected


def test_normalize_security_group_keeps_only_what_rules_need():
    raw = {
        "GroupId": "sg-1",
        "GroupName": "web",
        "VpcId": "vpc-1",
        "Description": "free text the rules do not need",
        "OwnerId": ACCOUNT,
        "Tags": [{"Key": "env", "Value": "prod"}],
        "IpPermissions": [],
        "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }
    resource = normalize_security_group(raw, ACCOUNT, "eu-west-2", NOW)

    assert resource.resource_id == f"arn:aws:ec2:eu-west-2:{ACCOUNT}:security-group/sg-1"
    assert resource.tags == {"env": "prod"}
    assert resource.properties == {"group_id": "sg-1", "vpc_id": "vpc-1"}
    assert resource.ingress_rules == ()  # egress is not collected


# ------------------------------------------------------------------ moto fixtures


def _open_group(region: str, name: str, port: int, cidr_key: str = "IpRanges") -> str:
    ec2 = boto3.client("ec2", region_name=region)
    group_id = ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
    source = {"CidrIp": "0.0.0.0/0"} if cidr_key == "IpRanges" else {"CidrIpv6": "::/0"}
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, cidr_key: [source]}],
    )
    return group_id


def _multi_region_trail(name: str = "org-audit", logging: bool = True) -> None:
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=f"{name}-logs")
    cloudtrail = boto3.client("cloudtrail", region_name="us-east-1")
    cloudtrail.create_trail(Name=name, S3BucketName=f"{name}-logs", IsMultiRegionTrail=True)
    if logging:
        cloudtrail.start_logging(Name=name)


@pytest.fixture
def assessed_session(aws, settings):
    return assume_assessment_role(CONNECTION, settings)


# ------------------------------------------------------------------ collection


def test_collects_security_groups_from_every_requested_region(assessed_session):
    _open_group("eu-west-2", "ssh-open", 22)
    _open_group("us-east-1", "rdp-open", 3389, "Ipv6Ranges")

    inventory = collect_inventory(
        assessed_session, ACCOUNT, "us-east-1", regions=["eu-west-2", "us-east-1"]
    )

    names = {(r.region, r.name) for r in inventory.of_type(SECURITY_GROUP)}
    assert ("eu-west-2", "ssh-open") in names
    assert ("us-east-1", "rdp-open") in names
    assert inventory.regions == ("eu-west-2", "us-east-1")
    assert inventory.gaps == ()


def test_unknown_region_in_scope_is_a_gap_not_silently_skipped(assessed_session):
    inventory = collect_inventory(
        assessed_session, ACCOUNT, "us-east-1", regions=["eu-west-2", "xx-nowhere-1"]
    )
    [gap] = inventory.gaps
    assert (gap.region, gap.reason) == ("xx-nowhere-1", "region not enabled")


def test_collects_trail_with_logging_status(assessed_session):
    _multi_region_trail()
    inventory = collect_inventory(assessed_session, ACCOUNT, "us-east-1", regions=["us-east-1"])

    [trail] = inventory.of_type(CLOUDTRAIL_TRAIL)
    assert trail.name == "org-audit"
    assert trail.properties["is_multi_region"] is True
    assert trail.properties["is_logging"] is True


def _deny(operation: str, region: str | None = None):
    """Event handler simulating AWS AccessDenied for one operation (optionally one region)."""

    def handler(model, params, **_):  # at before-call, params is the prepared request
        if model.name == operation and (region is None or f".{region}." in params["url"]):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, operation)

    return handler


def test_access_denied_in_one_region_becomes_a_gap(assessed_session):
    _open_group("us-east-1", "ssh-open", 22)
    assessed_session.events.register(
        "before-call.ec2.DescribeSecurityGroups", _deny("DescribeSecurityGroups", "eu-west-2")
    )

    inventory = collect_inventory(
        assessed_session, ACCOUNT, "us-east-1", regions=["eu-west-2", "us-east-1"]
    )

    [gap] = inventory.gaps
    assert (gap.resource_type, gap.region, gap.reason) == (
        SECURITY_GROUP,
        "eu-west-2",
        "AccessDenied",
    )
    assert any(r.name == "ssh-open" for r in inventory.of_type(SECURITY_GROUP))


def test_unreadable_trail_status_is_a_gap_not_a_guess(assessed_session):
    _multi_region_trail()
    assessed_session.events.register(
        "before-call.cloudtrail.GetTrailStatus", _deny("GetTrailStatus")
    )

    inventory = collect_inventory(assessed_session, ACCOUNT, "us-east-1", regions=["us-east-1"])

    assert inventory.of_type(CLOUDTRAIL_TRAIL) == []
    [gap] = inventory.gaps
    assert "org-audit" in gap.reason and "AccessDenied" in gap.reason


def test_read_only_violation_is_never_swallowed(assessed_session, monkeypatch):
    """A guard violation means a code bug: it must stop the scan, not become a gap."""
    from app.providers.aws import collectors

    def broken(*_args, **_kwargs):
        raise ReadOnlyViolation("Blocked by read-only guard: ec2:DeleteVpc is not allowed.")

    monkeypatch.setattr(collectors, "normalize_security_group", broken)
    _open_group("us-east-1", "any", 22)
    with pytest.raises(ReadOnlyViolation):
        collect_inventory(assessed_session, ACCOUNT, "us-east-1", regions=["us-east-1"])


# ------------------------------------------------------------------ end-to-end scans


def test_full_scan_finds_the_planted_weaknesses(aws, settings):
    ssh_group = _open_group("us-east-1", "ssh-open", 22)
    _open_group("us-east-1", "rdp-open", 3389)

    result = scan_aws(CONNECTION, settings, regions=["us-east-1"])

    found = {(f.rule_id, f.resource_name) for f in result.findings}
    assert ("NET-001", "ssh-open") in found
    assert ("NET-002", "rdp-open") in found
    assert ("AWS-LOG-001", None) in found  # no trail at all in this account
    [ssh] = [f for f in result.findings if f.resource_name == "ssh-open"]
    assert ssh.resource_id.endswith(ssh_group)
    assert ssh.evidence[0].source_operation == "ec2:DescribeSecurityGroups"


def test_full_scan_passes_cloudtrail_when_configured(aws, settings):
    _multi_region_trail()
    result = scan_aws(CONNECTION, settings, regions=["us-east-1"])

    [trail_check] = [r for r in result.results if r.rule_id == "AWS-LOG-001"]
    assert trail_check.status == CheckStatus.PASS


def test_scan_reports_not_evaluated_when_trails_cannot_be_read(aws, settings):
    session = assume_assessment_role(CONNECTION, settings)
    session.events.register("before-call.cloudtrail.DescribeTrails", _deny("DescribeTrails"))

    result = scan_aws(CONNECTION, settings, regions=["us-east-1"], session=session)

    [trail_check] = [r for r in result.results if r.rule_id == "AWS-LOG-001"]
    assert trail_check.status == CheckStatus.ERROR  # NOT a false "no CloudTrail" finding
    assert not [f for f in result.findings if f.rule_id == "AWS-LOG-001"]


def test_scan_stops_before_collecting_in_the_wrong_account(aws, settings):
    other = AwsConnection("999988887777", "subtletech-test-external-id", CONNECTION.role_name)
    session = assume_assessment_role(other, settings)  # credentials for a different account
    calls = []
    session.events.register("before-call.ec2", lambda **kw: calls.append(kw))

    with pytest.raises(WrongAccountError):
        scan_aws(CONNECTION, settings, session=session)
    assert calls == []  # nothing was collected


def test_cli_scan(aws, capsys):
    _open_group("us-east-1", "ssh-open", 22)
    code = cli_main(
        [
            "aws", "scan", "--account-id", ACCOUNT,
            "--external-id", "subtletech-test-external-id", "--regions", "us-east-1",
        ]
    )  # fmt: skip
    out = capsys.readouterr().out
    assert code == 0, out
    assert "Read-only." in out
    assert "[HIGH] NET-001 SSH open to the internet" in out
