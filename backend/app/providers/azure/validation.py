"""Azure connection validation: prove the connection works AND is safe, before any scan.

1. The platform has an Azure app identity configured.
2. A token can be obtained for the client's tenant (consent was given).
3. The subscription is visible, enabled, and belongs to the expected tenant.
4. Each read permission the enabled rules need actually works.
5. The read-only guard is active (a harmless delete attempt must be blocked locally).
"""

import logging
from collections.abc import Callable
from typing import Any

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

from app.core.config import Settings
from app.providers.azure import collect_arm
from app.providers.azure.arm import ArmReader
from app.providers.azure.errors import describe_azure_error
from app.providers.azure.guard import assessment_permissions, guarded_client
from app.providers.azure.session import ARM_SCOPE, AzureConnection, platform_credential
from app.providers.common import ReadOnlyViolation, ValidationReport

logger = logging.getLogger(__name__)

Probe = Callable[[Any, str], object]

# One cheap read per permission: fetch the first page only.
PERMISSION_PROBES: dict[str, Probe | None] = {
    "Microsoft.Network/networkSecurityGroups/read": lambda cred, sub: next(
        iter(guarded_client(NetworkManagementClient, cred, sub).network_security_groups.list_all()),
        None,
    ),
    "Microsoft.Storage/storageAccounts/read": lambda cred, sub: next(
        iter(guarded_client(StorageManagementClient, cred, sub).storage_accounts.list()), None
    ),
    "Microsoft.Sql/servers/read": lambda cred, sub: ArmReader(cred).get(
        f"/subscriptions/{sub}/providers/Microsoft.Sql/servers", collect_arm.SQL_API
    ),
    # Needs a server to probe; a missing permission is reported as a collection gap.
    "Microsoft.Sql/servers/firewallRules/read": None,
    "Microsoft.Insights/diagnosticSettings/read": lambda cred, sub: ArmReader(cred).get(
        f"/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings",
        collect_arm.DIAGNOSTICS_API,
    ),
    "Microsoft.Security/pricings/read": lambda cred, sub: ArmReader(cred).get(
        f"/subscriptions/{sub}/providers/Microsoft.Security/pricings", collect_arm.PRICINGS_API
    ),
}


def _problem_text(error: Exception) -> str:
    problem = describe_azure_error(error)
    return f"{problem.message} {problem.hint}".strip()


def validate_connection(
    connection: AzureConnection, settings: Settings, credential: Any | None = None
) -> ValidationReport:
    report = ValidationReport(account_id=connection.subscription_id)

    # 1. Platform identity
    try:
        credential = credential or platform_credential(connection, settings)
        report.add("Platform Azure identity", "ok", f"app {settings.azure_client_id}")
    except Exception as exc:
        report.add("Platform Azure identity", "failed", _problem_text(exc))
        return _finish(report)

    # 2. Token for the client's tenant
    try:
        credential.get_token(ARM_SCOPE)
        report.add("Sign in to client tenant", "ok", connection.tenant_id)
    except Exception as exc:
        report.add("Sign in to client tenant", "failed", _problem_text(exc))
        return _finish(report)

    # 3. Subscription visible, enabled, in the expected tenant. Fails CLOSED: a missing
    #    tenant or state counts as a failure, never as "probably fine".
    try:
        subscription = ArmReader(credential).subscription(connection.subscription_id)
        tenant = str(subscription.get("tenantId") or "")
        state = str(subscription.get("state") or "")
        if tenant.lower() != connection.tenant_id.lower():
            report.add(
                "Expected subscription",
                "failed",
                f"Belongs to tenant {tenant or 'unknown'}, not the one given.",
            )
            return _finish(report)
        if state.lower() != "enabled":
            report.add(
                "Expected subscription", "failed", f"Subscription state is {state or 'unknown'}."
            )
            return _finish(report)
        report.add("Expected subscription", "ok", str(subscription.get("displayName") or ""))
    except Exception as exc:
        report.add("Expected subscription", "failed", _problem_text(exc))
        return _finish(report)

    # 4. Read permissions needed by the enabled rules
    for permission in sorted(assessment_permissions() - {"Microsoft.Resources/subscriptions/read"}):
        probe = PERMISSION_PROBES.get(permission)
        if probe is None:
            report.add(f"Permission {permission}", "skipped", "Verified during collection.")
            continue
        try:
            probe(credential, connection.subscription_id)
            report.add(f"Permission {permission}", "ok")
        except Exception as exc:
            report.add(f"Permission {permission}", "failed", _problem_text(exc))

    # 5. Read-only guard: this delete must be stopped BEFORE reaching Azure.
    try:
        network = guarded_client(NetworkManagementClient, credential, connection.subscription_id)
        network.network_security_groups.begin_delete("guard-self-test", "does-not-exist")
        report.add("Read-only guard", "failed", "A write operation was NOT blocked.")
    except ReadOnlyViolation:
        report.add("Read-only guard", "ok", "Write operations are blocked locally.")
    except Exception as exc:
        report.add("Read-only guard", "failed", f"Write reached Azure: {_problem_text(exc)}")

    return _finish(report)


def _finish(report: ValidationReport) -> ValidationReport:
    logger.info(
        "azure connection validated",
        extra={
            "subscription_id": report.account_id,
            "ok": report.ok,
            "failed_checks": [c.name for c in report.checks if c.status == "failed"],
        },
    )
    return report
