"""Behaviour of the identity, storage, database, logging and Defender rules (R1)."""

from datetime import timedelta

import pytest

from app.domain.enums import CheckStatus, Provider
from app.rules.aws.iam_account import AdministratorAccessOnUsers, WeakPasswordPolicy
from app.rules.aws.iam_root import RootAccountAccessKeys, RootAccountWithoutMfa
from app.rules.aws.iam_users import ConsoleUserWithoutMfa, UnusedAccessKeys
from app.rules.aws.rds_public import RdsInstancePublic
from app.rules.aws.s3_public import S3AccountBlockPublicAccessOff, S3BucketPublic
from app.rules.azure.activity_log import ActivityLogNotExported
from app.rules.azure.defender import DefenderPlansDisabled
from app.rules.azure.sql_exposure import SqlServerAllowsAllAzureServices, SqlServerOpenToInternet
from app.rules.azure.storage_transport import StorageAccountAllowsHttp, StorageAccountWeakTls
from tests.factories import NOW, inventory, resource, storage_account

FAIL, PASS = CheckStatus.FAIL, CheckStatus.PASS
BLOCK_FLAGS = ("block_public_acls", "ignore_public_acls", "block_public_policy")
ALL_BLOCKED = dict.fromkeys((*BLOCK_FLAGS, "restrict_public_buckets"), True)
NONE_BLOCKED = dict.fromkeys(ALL_BLOCKED, False)


def aws(resource_type, name, **properties):
    return resource(Provider.AWS, resource_type, name, properties=properties)


def azure(resource_type, name, **properties):
    return resource(Provider.AZURE, resource_type, name, properties=properties)


def outcomes(rule, *resources, provider=Provider.AWS):
    return [(r.resource_name, r.status) for r in rule.evaluate(inventory(provider, *resources))]


def only_status(rule, *resources, provider=Provider.AWS):
    [(_name, status)] = outcomes(rule, *resources, provider=provider)
    return status


# ------------------------------------------------------------------ AWS IAM


@pytest.mark.parametrize(
    "rule, properties, expected",
    [
        (RootAccountWithoutMfa(), {"root_mfa_enabled": True}, PASS),
        (RootAccountWithoutMfa(), {"root_mfa_enabled": False}, FAIL),
        (RootAccountWithoutMfa(), {}, FAIL),  # unknown is never a pass
        (RootAccountAccessKeys(), {"root_access_keys_present": False}, PASS),
        (RootAccountAccessKeys(), {"root_access_keys_present": True}, FAIL),
        (RootAccountAccessKeys(), {}, FAIL),
    ],
)
def test_root_user_rules(rule, properties, expected):
    assert only_status(rule, aws("aws.iam.account", "root user", **properties)) == expected


def test_root_findings_are_account_level():
    [result] = RootAccountWithoutMfa().evaluate(
        inventory(Provider.AWS, aws("aws.iam.account", "root user", root_mfa_enabled=False))
    )
    assert result.resource_id is None and result.evidence


@pytest.mark.parametrize(
    "password, mfa, expected",
    [(False, False, PASS), (True, True, PASS), (True, False, FAIL)],
)
def test_console_user_without_mfa(password, mfa, expected):
    user = aws("aws.iam.user", "alice", password_enabled=password, mfa_active=mfa)
    assert outcomes(ConsoleUserWithoutMfa(), user) == [("alice", expected)]


def _key(last_used_days_ago=None, rotated_days_ago=None):
    def when(days):
        return None if days is None else (NOW - timedelta(days=days)).isoformat()

    return {
        "slot": 1,
        "active": True,
        "last_used": when(last_used_days_ago),
        "last_rotated": when(rotated_days_ago),
    }


@pytest.mark.parametrize(
    "key, expected",
    [
        (_key(last_used_days_ago=3, rotated_days_ago=400), PASS),
        (_key(last_used_days_ago=46, rotated_days_ago=400), FAIL),
        (_key(rotated_days_ago=60), FAIL),  # never used, created 60 days ago
        (_key(rotated_days_ago=10), PASS),  # new and not used yet: not reported
    ],
)
def test_unused_access_keys(key, expected):
    user = aws("aws.iam.user", "ci-bot", access_keys=[key])
    assert outcomes(UnusedAccessKeys(), user) == [("ci-bot", expected)]


@pytest.mark.parametrize(
    "properties, expected",
    [
        ({"exists": True, "minimum_length": 14}, PASS),
        ({"exists": True, "minimum_length": 8}, FAIL),
        ({"exists": False}, FAIL),
    ],
)
def test_password_policy(properties, expected):
    policy = aws("aws.iam.password_policy", "account password policy", **properties)
    assert only_status(WeakPasswordPolicy(), policy) == expected


@pytest.mark.parametrize(
    "users, groups, roles, expected",
    [
        ([], [], ["OrganizationAccountAccessRole"], PASS),  # roles are evidence only
        (["bob"], [], [], FAIL),
        ([], ["admins"], [], FAIL),
    ],
)
def test_administrator_access_on_users(users, groups, roles, expected):
    policy = aws(
        "aws.iam.admin_policy", "AdministratorAccess", users=users, groups=groups, roles=roles
    )
    assert only_status(AdministratorAccessOnUsers(), policy) == expected


# ------------------------------------------------------------------ AWS S3 / RDS


def test_s3_account_block_public_access():
    rule = S3AccountBlockPublicAccessOff()
    assert only_status(rule, aws("aws.s3.account_settings", "s3", **ALL_BLOCKED)) == PASS
    partial = {**ALL_BLOCKED, "restrict_public_buckets": False}
    [result] = rule.evaluate(
        inventory(Provider.AWS, aws("aws.s3.account_settings", "s3", **partial))
    )
    assert result.status == FAIL
    assert "restrict_public_buckets" in result.evidence[0].summary


@pytest.mark.parametrize(
    "bucket, account, expected",
    [
        ({"policy_public": False, "acl_public": False}, NONE_BLOCKED, PASS),
        ({"policy_public": True, "acl_public": False}, NONE_BLOCKED, FAIL),
        ({"policy_public": False, "acl_public": True}, NONE_BLOCKED, FAIL),
        # Block Public Access neutralizes the exposure, at bucket or account level:
        ({"policy_public": True, "restrict_public_buckets": True}, NONE_BLOCKED, PASS),
        ({"policy_public": True}, {**NONE_BLOCKED, "restrict_public_buckets": True}, PASS),
        ({"acl_public": True}, {**NONE_BLOCKED, "ignore_public_acls": True}, PASS),
        # ...but only the setting that matches the kind of exposure:
        ({"policy_public": True}, {**NONE_BLOCKED, "ignore_public_acls": True}, FAIL),
    ],
)
def test_s3_bucket_public(bucket, account, expected):
    status = only_status(
        S3BucketPublic(),
        aws("aws.s3.bucket", "data", **bucket),
        aws("aws.s3.account_settings", "s3", **account),
    )
    assert status == expected


def test_rds_instance_public():
    assert outcomes(
        RdsInstancePublic(),
        aws("aws.rds.db_instance", "public-db", publicly_accessible=True, engine="postgres"),
        aws("aws.rds.db_instance", "private-db", publicly_accessible=False),
    ) == [("public-db", FAIL), ("private-db", PASS)]


# ------------------------------------------------------------------ Azure storage


@pytest.mark.parametrize("https_only, expected", [(True, PASS), (False, FAIL), (None, FAIL)])
def test_storage_https_only(https_only, expected):
    account = storage_account("s", False, https_only=https_only)
    assert only_status(StorageAccountAllowsHttp(), account, provider=Provider.AZURE) == expected


@pytest.mark.parametrize(
    "version, expected",
    [("TLS1_2", PASS), ("TLS1_3", PASS), ("TLS1_0", FAIL), ("TLS1_1", FAIL), (None, FAIL)],
)
def test_storage_minimum_tls(version, expected):
    account = storage_account("s", False, minimum_tls_version=version)
    assert only_status(StorageAccountWeakTls(), account, provider=Provider.AZURE) == expected


# ------------------------------------------------------------------ Azure SQL


def sql(name, *rules, public_network_access="Enabled"):
    return azure(
        "azure.sql.server",
        name,
        public_network_access=public_network_access,
        firewall_rules=[{"name": n, "start_ip": s, "end_ip": e} for n, s, e in rules],
    )


ALL_INTERNET = ("AllowAll", "0.0.0.0", "255.255.255.255")
ALL_AZURE = ("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0")
OFFICE = ("office", "203.0.113.10", "203.0.113.10")


@pytest.mark.parametrize(
    "server, internet, azure_services",
    [
        (sql("a", ALL_INTERNET), FAIL, PASS),
        (sql("a", ALL_AZURE), PASS, FAIL),
        (sql("a", OFFICE), PASS, PASS),
        (sql("a"), PASS, PASS),
        # Public network access off: Azure ignores the IP firewall entirely.
        (sql("a", ALL_INTERNET, ALL_AZURE, public_network_access="Disabled"), PASS, PASS),
    ],
)
def test_sql_firewall_rules(server, internet, azure_services):
    assert only_status(SqlServerOpenToInternet(), server, provider=Provider.AZURE) == internet
    assert (
        only_status(SqlServerAllowsAllAzureServices(), server, provider=Provider.AZURE)
        == azure_services
    )


# ------------------------------------------------------------------ Azure logging / Defender


def setting(*categories, destination=True):
    return {"name": "s", "has_destination": destination, "enabled_categories": list(categories)}


@pytest.mark.parametrize(
    "settings, expected",
    [
        ([setting("Administrative", "Security", "Policy")], PASS),
        ([setting("allLogs")], PASS),
        ([setting("Administrative")], FAIL),  # Security missing
        ([setting("Administrative", "Security", destination=False)], FAIL),
        ([], FAIL),
    ],
)
def test_activity_log_export(settings, expected):
    export = azure("azure.monitor.activity_log_export", "Activity Log", settings=settings)
    assert only_status(ActivityLogNotExported(), export, provider=Provider.AZURE) == expected


KEY_PLANS = {"VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults"}


def test_defender_plans():
    rule = DefenderPlansDisabled()
    all_on = dict.fromkeys(KEY_PLANS, "Standard") | {"Containers": "Free"}
    on = azure("azure.security.defender_plans", "Defender", plans=all_on)
    assert only_status(rule, on, provider=Provider.AZURE) == PASS

    partial = {**all_on, "KeyVaults": "Free"}
    del partial["SqlServers"]  # not returned at all: never assumed to be on
    off = azure("azure.security.defender_plans", "Defender", plans=partial)
    [result] = rule.evaluate(inventory(Provider.AZURE, off))
    assert result.status == FAIL
    assert result.evidence[0].observed == {
        "not_standard": {"SqlServers": None, "KeyVaults": "Free"}
    }
