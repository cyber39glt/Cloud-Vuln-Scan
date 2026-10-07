"""Azure connector tests. HTTP to Azure is simulated with the `responses` library and
a fake credential: no Azure account, token or network is involved."""

import re
from pathlib import Path

import pytest
import responses
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.core.rest import HttpRequest
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

from app.core.config import Settings
from app.domain.enums import Provider
from app.providers.azure import guard
from app.providers.azure.arm import ArmReader
from app.providers.azure.errors import describe_azure_error
from app.providers.azure.guard import (
    ReadOnlyViolation,
    assessment_permissions,
    guarded_client,
    permission_for,
)
from app.providers.azure.session import AzureConnection, admin_consent_url, platform_credential
from app.providers.azure.validation import PERMISSION_PROBES, validate_connection
from app.rules.registry import ALL_RULES
from tests.azure_fakes import SUB, TENANT, FakeCredential, arm_url, mock_subscription

CONNECTION = AzureConnection(TENANT, SUB)
_url = arm_url
_subscription = mock_subscription


def _lists(rsps, nsg_status: int = 200) -> None:
    nsg_body = (
        {"value": []}
        if nsg_status == 200
        else {"error": {"code": "AuthorizationFailed", "message": "no access"}}
    )
    rsps.get(
        _url(f"/subscriptions/{SUB}/providers/Microsoft.Network/networkSecurityGroups"),
        json=nsg_body,
        status=nsg_status,
    )
    rsps.get(
        _url(f"/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts"),
        json={"value": []},
    )


# ------------------------------------------------------------------ guard


@pytest.mark.parametrize(
    "path, permission",
    [
        (f"/subscriptions/{SUB}", "Microsoft.Resources/subscriptions/read"),
        ("/subscriptions", "Microsoft.Resources/subscriptions/read"),
        (
            f"/subscriptions/{SUB}/resourceGroups/rg",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
        ),
        (
            f"/subscriptions/{SUB}/providers/Microsoft.Network/networkSecurityGroups",
            "Microsoft.Network/networkSecurityGroups/read",
        ),
        (
            f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n1",
            "Microsoft.Network/networkSecurityGroups/read",
        ),
        (
            f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/blobServices/default",
            "Microsoft.Storage/storageAccounts/blobServices/read",
        ),
        (
            f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/secrets/s",
            "Microsoft.KeyVault/vaults/secrets/read",
        ),
    ],
)  # fmt: skip
def test_permission_for_path(path, permission):
    assert permission_for(path) == permission


def test_guard_allows_listed_reads():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        _lists(rsps)
        client = guarded_client(NetworkManagementClient, FakeCredential(), SUB)
        assert list(client.network_security_groups.list_all()) == []


@pytest.mark.parametrize(
    "attempt, blocked",
    [
        (lambda n, s: n.network_security_groups.begin_delete("rg", "nsg"), "DELETE"),
        (
            lambda n, s: n.network_security_groups.begin_create_or_update("rg", "nsg", {}),
            "PUT",
        ),
        (lambda n, s: s.storage_accounts.list_keys("rg", "acct"), "POST"),  # secrets!
        (lambda n, s: list(n.virtual_networks.list_all()), "virtualNetworks/read"),  # not listed
    ],
)
def test_guard_blocks_before_anything_is_sent(attempt, blocked):
    network = guarded_client(NetworkManagementClient, FakeCredential(), SUB)
    storage = guarded_client(StorageManagementClient, FakeCredential(), SUB)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        with pytest.raises(ReadOnlyViolation, match=blocked):
            attempt(network, storage)
        assert len(rsps.calls) == 0  # no HTTP request was sent


def test_guard_blocks_data_plane_hosts():
    """Key Vault and blob storage hosts hold secrets and data: never contacted."""
    policy = guard.ReadOnlyPolicy(assessment_permissions())
    from azure.core.pipeline import PipelineContext, PipelineRequest

    for url in (
        "https://myvault.vault.azure.net/secrets/db",
        "https://acct.blob.core.windows.net/c",
    ):
        request = PipelineRequest(HttpRequest("GET", url), PipelineContext(None))
        with pytest.raises(ReadOnlyViolation, match="host"):
            policy.on_request(request)


def test_arm_reader_is_guarded_too():
    reader = ArmReader(FakeCredential())
    with pytest.raises(ReadOnlyViolation):
        reader.get(
            f"/subscriptions/{SUB}/providers/Microsoft.Compute/virtualMachines", "2024-01-01"
        )


def test_assessment_permissions_are_reads_and_cover_rules():
    permissions = assessment_permissions()
    assert all(p.endswith("/read") for p in permissions)
    for rule in ALL_RULES:
        assert set(rule.metadata.required_permissions.get(Provider.AZURE, ())) <= permissions


def test_rule_declaring_a_non_read_permission_is_rejected(monkeypatch):
    bad = ALL_RULES[0].metadata.model_copy(
        update={
            "required_permissions": {
                Provider.AZURE: ("Microsoft.Storage/storageAccounts/listkeys/action",)
            }
        }
    )
    monkeypatch.setattr(guard, "ALL_RULES", (type("BadRule", (), {"metadata": bad})(),))
    with pytest.raises(ValueError, match="non-read"):
        assessment_permissions()


def test_every_permission_has_a_probe_or_is_explicitly_skipped():
    expected = assessment_permissions() - {"Microsoft.Resources/subscriptions/read"}
    assert expected <= set(PERMISSION_PROBES)


def test_azure_clients_are_only_created_through_the_guard():
    """Every Azure SDK client must be built by guarded_client(); the only other HTTP
    client is ArmReader, whose first policy is the guard."""
    app_dir = Path(__file__).parents[1] / "app"
    creators = sorted(
        p.relative_to(app_dir).as_posix()
        for p in app_dir.rglob("*.py")
        if re.search(r"\b\w*(ManagementClient|PipelineClient)\(", p.read_text(encoding="utf-8"))
    )
    assert creators == ["providers/azure/arm.py"]


# ------------------------------------------------------------------ session


@pytest.mark.parametrize("tenant, sub", [("not-a-guid", SUB), (TENANT, "123"), ("", SUB)])
def test_connection_requires_guids(tenant, sub):
    with pytest.raises(ValueError, match="GUID"):
        AzureConnection(tenant, sub)


def test_platform_credential_requires_configuration():
    with pytest.raises(RuntimeError, match="AZURE_CLIENT_ID"):
        platform_credential(CONNECTION, Settings(_env_file=None))


def test_platform_credential_is_scoped_to_the_client_tenant():
    settings = Settings(
        _env_file=None,
        azure_client_id="33333333-3333-3333-3333-333333333333",
        azure_client_secret="dev-secret-value",
    )
    credential = platform_credential(CONNECTION, settings)
    assert isinstance(credential, ClientSecretCredential)
    assert "dev-secret-value" not in repr(settings)


def test_admin_consent_url():
    assert admin_consent_url(TENANT, "app-id") == (
        f"https://login.microsoftonline.com/{TENANT}/adminconsent?client_id=app-id"
    )


# ------------------------------------------------------------------ validation


def _statuses(report):
    return {c.name: c.status for c in report.checks}


def test_validation_happy_path(settings):
    with responses.RequestsMock() as rsps:
        _subscription(rsps)
        _lists(rsps)
        report = validate_connection(CONNECTION, settings, credential=FakeCredential())

    statuses = _statuses(report)
    assert report.ok, report.checks
    assert statuses["Sign in to client tenant"] == "ok"
    assert statuses["Expected subscription"] == "ok"
    assert statuses["Permission Microsoft.Network/networkSecurityGroups/read"] == "ok"
    assert statuses["Permission Microsoft.Storage/storageAccounts/read"] == "ok"
    assert statuses["Read-only guard"] == "ok"


@pytest.mark.parametrize(
    "tenant, state, expected",
    [
        ("99999999-9999-9999-9999-999999999999", "Enabled", "Belongs to tenant 9999"),
        (None, "Enabled", "Belongs to tenant unknown"),  # missing = fail CLOSED
        (TENANT, "Disabled", "state is Disabled"),
        (TENANT, None, "state is unknown"),
    ],
)
def test_validation_rejects_unexpected_subscriptions(settings, tenant, state, expected):
    with responses.RequestsMock() as rsps:
        _subscription(rsps, tenant=tenant, state=state)
        report = validate_connection(CONNECTION, settings, credential=FakeCredential())

    assert not report.ok
    assert report.checks[-1].name == "Expected subscription"
    assert expected in report.checks[-1].detail


def test_validation_explains_missing_consent(settings):
    error = ClientAuthenticationError("AADSTS700016: Application with identifier was not found")
    report = validate_connection(CONNECTION, settings, credential=FakeCredential(error))

    assert not report.ok
    assert report.checks[-1].name == "Sign in to client tenant"
    assert "admin consent" in report.checks[-1].detail
    assert len(report.checks) == 2  # nothing else attempted


def test_validation_explains_missing_role(settings):
    with responses.RequestsMock() as rsps:
        _subscription(rsps)
        _lists(rsps, nsg_status=403)
        report = validate_connection(CONNECTION, settings, credential=FakeCredential())

    assert not report.ok
    failed = [c for c in report.checks if c.status == "failed"]
    assert [c.name for c in failed] == ["Permission Microsoft.Network/networkSecurityGroups/read"]
    assert "Reader" in failed[0].detail


def test_validation_without_platform_identity(settings):
    report = validate_connection(CONNECTION, settings)
    assert not report.ok
    assert report.checks[0].name == "Platform Azure identity"
    assert "AZURE_CLIENT_ID" in report.checks[0].detail


# ------------------------------------------------------------------ errors


@pytest.mark.parametrize(
    "code, fragment",
    [("AADSTS7000222", "expired"), ("AADSTS7000215", "wrong"), ("AADSTS90002", "not found")],
)
def test_sign_in_errors_get_plain_language(code, fragment):
    problem = describe_azure_error(ClientAuthenticationError(f"{code}: details"))
    assert problem.code == code
    assert fragment in problem.message


def test_unknown_arm_error_is_redacted():
    error = HttpResponseError(message="password=hunter2")
    error.status_code = 500
    problem = describe_azure_error(error)
    assert "hunter2" not in problem.hint
