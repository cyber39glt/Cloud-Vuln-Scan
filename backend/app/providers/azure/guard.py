"""Application-side read-only guard for Azure (layer 2 of ADR 0002).

Azure SDK clients send every request through a "pipeline" of policies. We add our
own policy at the front of that pipeline. Before a request leaves (and before an
access token is even attached) it must be:

  1. a GET request: Azure Resource Manager reads are GETs; writes are PUT, PATCH or
     DELETE, and "actions" such as listKeys (which returns storage secrets) are POSTs;
  2. sent to Azure Resource Manager (management.azure.com): never to data-plane hosts
     such as Key Vault or blob storage, where secrets and business data live;
  3. for a resource type on an explicit allowlist derived from the enabled rules.

Anything else raises ReadOnlyViolation and is never sent.
"""

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from azure.core.pipeline import PipelineRequest
from azure.core.pipeline.policies import SansIOHTTPPolicy

from app.domain.enums import Provider
from app.providers.common import ReadOnlyViolation
from app.rules.registry import ALL_RULES

ARM_HOST = "management.azure.com"

# Bounded network behaviour, so one slow or throttling tenant cannot stall the scan
# worker for hours (SDK defaults: 300 s reads, 10 retries, a week of total retrying).
HTTP_LIMITS: dict[str, int] = {
    "connection_timeout": 10,  # seconds to connect
    "read_timeout": 60,  # seconds waiting for a response
    "retry_total": 3,  # retries per request
    "timeout": 300,  # seconds for one request including all its retries
}

# Calls the connector itself makes, beyond what rules need.
CONNECTOR_PERMISSIONS: frozenset[str] = frozenset({"Microsoft.Resources/subscriptions/read"})

_READ_PERMISSION = re.compile(r"^Microsoft\.\w+(/\w+)+/read$", re.IGNORECASE)

__all__ = ["ReadOnlyViolation", "ReadOnlyPolicy", "assessment_permissions", "permission_for"]


def assessment_permissions() -> frozenset[str]:
    """Exactly the Azure read permissions the enabled rules declare, plus the
    connector's own. Anything that is not a '<provider>/<type>/read' is refused."""
    from_rules = {
        permission
        for rule in ALL_RULES
        for permission in rule.metadata.required_permissions.get(Provider.AZURE, ())
    }
    permissions = frozenset(from_rules | CONNECTOR_PERMISSIONS)
    not_reads = [p for p in permissions if not _READ_PERMISSION.match(p)]
    if not_reads:
        raise ValueError(f"non-read Azure permissions cannot be allowed: {not_reads}")
    return permissions


def permission_for(path: str) -> str:
    """Translate an ARM URL path into the Azure RBAC read permission it needs.

    /subscriptions/{id}
        -> Microsoft.Resources/subscriptions/read
    /subscriptions/{id}/resourceGroups/{rg}
        -> Microsoft.Resources/subscriptions/resourceGroups/read
    .../providers/Microsoft.Network/networkSecurityGroups[/{name}]
        -> Microsoft.Network/networkSecurityGroups/read
    .../providers/Microsoft.Storage/storageAccounts/{n}/blobServices/default
        -> Microsoft.Storage/storageAccounts/blobServices/read
    """
    segments = [s for s in path.split("/") if s]
    lowered = [s.lower() for s in segments]
    if "providers" in lowered:
        index = len(lowered) - 1 - lowered[::-1].index("providers")
        namespace = segments[index + 1]
        types = segments[index + 2 :: 2]  # type, name, sub-type, name, ...
        return f"{namespace}/{'/'.join(types)}/read"
    if lowered[:1] == ["subscriptions"] and len(lowered) >= 3 and lowered[2] == "resourcegroups":
        return "Microsoft.Resources/subscriptions/resourceGroups/read"
    return "Microsoft.Resources/subscriptions/read"


class ReadOnlyPolicy(SansIOHTTPPolicy):
    """azure-core pipeline policy enforcing the three rules in the module docstring."""

    def __init__(self, allowed_permissions: Iterable[str]) -> None:
        super().__init__()
        self._allowed = {p.lower() for p in allowed_permissions}

    def on_request(self, request: PipelineRequest[Any]) -> None:
        http = request.http_request
        url = urlparse(http.url)
        if http.method.upper() != "GET":
            raise ReadOnlyViolation(f"Blocked by read-only guard: {http.method} is not allowed.")
        if url.hostname != ARM_HOST:
            raise ReadOnlyViolation(
                f"Blocked by read-only guard: host {url.hostname} is not allowed."
            )
        permission = permission_for(url.path)
        if permission.lower() not in self._allowed:
            raise ReadOnlyViolation(f"Blocked by read-only guard: {permission} is not allowed.")


def guarded_client(client_class: type, credential: Any, *args: Any, **kwargs: Any) -> Any:
    """The ONLY way the app creates Azure SDK clients, with the guard in two places:

    - first in the pipeline (per call), so a disallowed call is refused before any
      other policy runs;
    - again after the retry policy (per retry), right before the token is attached
      and the request is sent. Policies in between can CREATE requests of their own:
      the SDK's automatic resource-provider registration answers a "provider not
      registered" error with a POST .../register (a write), and the redirect policy
      follows 3xx responses to other URLs. Those requests start below the first
      guard, so only the second one sees them. (Found in the M13 security review.)
    """
    policy = ReadOnlyPolicy(assessment_permissions())
    return client_class(
        credential,
        *args,
        per_call_policies=[policy],
        per_retry_policies=[policy],
        **(HTTP_LIMITS | kwargs),
    )
