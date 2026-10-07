"""AWS connector tests. moto simulates AWS inside the test process: no real AWS
account, network or credentials are involved."""

import re
from pathlib import Path

import boto3
import botocore.session
import pytest
from botocore.exceptions import ClientError

from app.cli import main as cli_main
from app.core.config import Settings
from app.domain.enums import Provider
from app.providers.aws import guard
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.guard import (
    OPERATION_FOR_PERMISSION,
    PLATFORM_OPERATIONS,
    READ_ONLY_EXCEPTIONS,
    READ_PREFIXES,
    ReadOnlyViolation,
    assessment_operations,
    assessment_permissions,
    guarded_session,
)
from app.providers.aws.session import (
    EXTERNAL_ID_PATTERN,
    AwsConnection,
    assume_assessment_role,
    generate_external_id,
    platform_session,
)
from app.providers.aws.validation import PERMISSION_PROBES, validate_connection
from app.rules.registry import ALL_RULES

MOTO_ACCOUNT = "123456789012"  # moto's default account
EXTERNAL_ID = "subtletech-test-external-id"


def connection(account_id: str = MOTO_ACCOUNT) -> AwsConnection:
    return AwsConnection(account_id, EXTERNAL_ID, "SubtleTechSecurityAssessment")


# ------------------------------------------------------------------ the guard


def test_guard_allows_listed_operation(aws):
    session = guarded_session({"ec2:DescribeSecurityGroups"}, region_name="us-east-1")
    session.client("ec2").describe_security_groups()  # does not raise


def test_guard_blocks_before_anything_is_sent(aws):
    session = guarded_session({"ec2:DescribeSecurityGroups"}, region_name="us-east-1")
    sent = []
    session.events.register("before-send", lambda **kw: sent.append(kw))

    ec2 = session.client("ec2")
    with pytest.raises(ReadOnlyViolation, match="ec2:DeleteSecurityGroup"):
        ec2.delete_security_group(GroupId="sg-12345678")
    with pytest.raises(ReadOnlyViolation, match="ec2:RunInstances"):
        ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)

    assert sent == []  # no HTTP request was even prepared for sending


def test_platform_identity_can_only_identify_itself_and_assume_roles(aws, settings):
    platform = platform_session(settings)
    platform.client("sts").get_caller_identity()
    with pytest.raises(ReadOnlyViolation):
        platform.client("ec2", region_name="us-east-1").describe_regions()
    assert frozenset({"sts:GetCallerIdentity", "sts:AssumeRole"}) == PLATFORM_OPERATIONS


def test_assessment_allowlist_is_read_only_and_exactly_what_rules_need():
    operations = assessment_operations()
    assert all(
        op in READ_ONLY_EXCEPTIONS or op.split(":")[1].startswith(READ_PREFIXES)
        for op in operations
    )
    assert {"iam:GenerateCredentialReport"} == READ_ONLY_EXCEPTIONS  # changes need review
    assert "sts:AssumeRole" not in operations  # no role chaining from client accounts
    for rule in ALL_RULES:
        for permission in rule.metadata.required_permissions.get(Provider.AWS, ()):
            assert OPERATION_FOR_PERMISSION.get(permission, permission) in operations


def test_allowlisted_operations_exist_in_the_aws_sdk():
    """Catches typos: a misspelled operation would silently never be allowed."""
    botocore_session = botocore.session.get_session()
    for operation in assessment_operations() | PLATFORM_OPERATIONS:
        service, name = operation.split(":")
        assert name in botocore_session.get_service_model(service).operation_names, operation


def test_rule_declaring_a_write_permission_is_rejected(monkeypatch):
    bad_rule = ALL_RULES[0]
    bad_meta = bad_rule.metadata.model_copy(
        update={"required_permissions": {Provider.AWS: ("ec2:DeleteSecurityGroup",)}}
    )
    fake = type("BadRule", (), {"metadata": bad_meta})()
    monkeypatch.setattr(guard, "ALL_RULES", (fake,))
    with pytest.raises(ValueError, match="non-read"):
        assessment_operations()


def test_every_permission_has_a_probe_or_is_explicitly_skipped():
    assert assessment_permissions() | {"ec2:DescribeRegions"} <= set(PERMISSION_PROBES)


# ------------------------------------------------------------------ session


@pytest.mark.parametrize(
    "account_id", ["12345", "12345678901a", "1234567890123", "", "١٢٣٤٥٦٧٨٩٠١٢"]
)
def test_connection_rejects_invalid_account_ids(account_id):
    with pytest.raises(ValueError, match="12 digits"):
        connection(account_id)


@pytest.mark.parametrize("external_id", ["x", "has space", "semi;colon", "a" * 1225])
def test_connection_rejects_invalid_external_ids(external_id):
    with pytest.raises(ValueError, match="ExternalId"):
        AwsConnection(MOTO_ACCOUNT, external_id, "Role")


def test_role_arn_is_built_from_account_id():
    assert connection().role_arn == f"arn:aws:iam::{MOTO_ACCOUNT}:role/SubtleTechSecurityAssessment"


def test_external_ids_are_unique_and_valid():
    ids = {generate_external_id("SubtleTech") for _ in range(50)}
    assert len(ids) == 50
    assert all(EXTERNAL_ID_PATTERN.fullmatch(i) and i.startswith("subtletech-") for i in ids)


def test_assumed_session_is_guarded(aws, settings):
    session = assume_assessment_role(connection(), settings)

    session.client("ec2").describe_security_groups()  # allowed read
    with pytest.raises(ReadOnlyViolation):
        session.client("ec2").create_security_group(GroupName="x", Description="x")
    # No role chaining onward. Parameters are deliberately invalid: the guard must
    # refuse the operation before botocore even validates them.
    with pytest.raises(ReadOnlyViolation):
        session.client("sts").assume_role(RoleArn="x", RoleSessionName="x")


def test_session_name_identifies_the_consultancy(aws, settings):
    calls = []
    platform = platform_session(settings)
    platform.events.register(
        "before-parameter-build.sts.AssumeRole", lambda params, **_: calls.append(dict(params))
    )
    assume_assessment_role(connection(), settings, platform=platform)

    [params] = calls
    assert re.fullmatch(r"SubtleTech-assessment-[0-9a-f]{8}", params["RoleSessionName"])
    assert params["ExternalId"] == EXTERNAL_ID
    assert params["DurationSeconds"] == 3600


# ------------------------------------------------------------------ validation


def test_validation_happy_path(aws, settings):
    report = validate_connection(connection(), settings)

    statuses = {c.name: c.status for c in report.checks}
    assert report.ok, report.checks
    assert statuses["Assume assessment role"] == "ok"
    assert statuses["Expected account"] == "ok"
    assert statuses["Permission ec2:DescribeSecurityGroups"] == "ok"
    assert statuses["Permission cloudtrail:GetTrailStatus"] == "skipped"
    assert statuses["Read-only guard"] == "ok"


def test_validation_detects_wrong_account(aws, settings, monkeypatch):
    """If the role ARN leads somewhere unexpected, stop before reading anything."""
    from app.providers.aws import validation

    def assume_into_other_account(conn, s, platform=None):
        return assume_assessment_role(connection("999988887777"), s, platform=platform)

    monkeypatch.setattr(validation, "assume_assessment_role", assume_into_other_account)
    report = validate_connection(connection(), settings)

    assert not report.ok
    assert report.checks[-1].name == "Expected account"
    assert report.checks[-1].status == "failed"


class _DeniedPlatform:
    """A platform identity whose AssumeRole is refused, like a wrong ExternalId."""

    class _Sts:
        def get_caller_identity(self):
            return {"Arn": "arn:aws:iam::123456789012:user/scanner", "Account": "123456789012"}

        def assume_role(self, **_):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized ExternalId x"}},
                "AssumeRole",
            )

    def client(self, *_, **__):
        return self._Sts()


def test_validation_explains_access_denied(settings):
    report = validate_connection(connection(), settings, platform=_DeniedPlatform())

    assert not report.ok
    failed = report.checks[-1]
    assert failed.name == "Assume assessment role"
    assert "ExternalId" in failed.detail
    assert len(report.checks) == 2  # nothing else attempted


def test_validation_without_platform_credentials(monkeypatch, settings, tmp_path):
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    report = validate_connection(connection(), settings)

    assert not report.ok
    assert report.checks[0].name == "Platform AWS identity"
    assert "AWS_ACCESS_KEY_ID" in report.checks[0].detail


# ------------------------------------------------------------------ errors


def _client_error(code: str, message: str = "msg") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


def test_known_errors_get_plain_language():
    problem = describe_aws_error(_client_error("InvalidClientTokenId"))
    assert problem.code == "InvalidClientTokenId"
    assert "AWS_ACCESS_KEY_ID" in problem.hint


def test_unknown_error_text_is_redacted():
    problem = describe_aws_error(_client_error("Weird", "leaked AKIAIOSFODNN7EXAMPLE"))
    assert "AKIAIOSFODNN7EXAMPLE" not in problem.hint


# ------------------------------------------------------------------ CLI + template


def test_cli_generates_external_id(capsys):
    assert cli_main(["aws", "external-id"]) == 0
    assert capsys.readouterr().out.strip().startswith("subtletech-")


def test_cli_rejects_invalid_input(capsys):
    assert cli_main(["aws", "validate", "--account-id", "123", "--external-id", "ab"]) == 1
    assert "12 digits" in capsys.readouterr().out


def test_cli_validate_end_to_end(aws, capsys):
    code = cli_main(["aws", "validate", "--account-id", MOTO_ACCOUNT, "--external-id", EXTERNAL_ID])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "[ OK ] Read-only guard" in out
    assert "Connection is ready." in out


def test_onboarding_template_matches_platform_settings():
    template = (
        Path(__file__).parents[2] / "infra" / "aws" / "client-onboarding-role.yaml"
    ).read_text(encoding="utf-8")
    assert f"Default: {Settings(_env_file=None).aws_assessment_role_name}" in template
    assert "sts:ExternalId" in template
    assert "MaxSessionDuration: 3600" in template
    assert "Effect: Deny" in template
    # The only Allow in the template is the trust statement for AssumeRole.
    assert template.count("Effect: Allow") == 1


def test_boto3_is_only_used_by_the_providers_package():
    """Rules and domain code must never call AWS directly."""
    app_dir = Path(__file__).parents[1] / "app"
    offenders = [
        p.relative_to(app_dir).as_posix()
        for p in app_dir.rglob("*.py")
        if "providers" not in p.parts
        and re.search(r"^\s*(import|from)\s+(boto3|botocore)", p.read_text(encoding="utf-8"), re.M)
    ]
    assert offenders == []


def test_boto3_session_is_not_shared_between_connections(aws, settings):
    a = assume_assessment_role(connection(), settings)
    b = assume_assessment_role(connection(), settings)
    assert a is not b
    assert isinstance(a, boto3.Session)


def test_unguarded_sessions_cannot_be_created_elsewhere():
    """Every boto3 Session must come from guarded_session(); a plain boto3.Session()
    anywhere else in the app would bypass the read-only guard."""
    app_dir = Path(__file__).parents[1] / "app"
    creators = [
        p.relative_to(app_dir).as_posix()
        for p in app_dir.rglob("*.py")
        if re.search(r"boto3\.(Session|client|resource)\(", p.read_text(encoding="utf-8"))
    ]
    assert creators == ["providers/aws/guard.py"]
