"""A minimal, guarded reader for Azure Resource Manager (ARM) REST calls that the
SDK packages do not cover well (e.g. subscription details including the tenant ID).

Built on azure-core's public PipelineClient with an explicit policy order: the
read-only guard runs FIRST, before retries and before a token is even attached.
"""

from typing import Any

from azure.core import PipelineClient
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.policies import (
    BearerTokenCredentialPolicy,
    HeadersPolicy,
    RetryPolicy,
    UserAgentPolicy,
)
from azure.core.rest import HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat

from app.providers.azure.guard import ARM_HOST, ReadOnlyPolicy, assessment_permissions
from app.providers.azure.session import ARM_SCOPE

SUBSCRIPTIONS_API_VERSION = "2022-12-01"


class ArmReader:
    def __init__(self, credential: Any) -> None:
        self._client = PipelineClient(
            base_url=f"https://{ARM_HOST}",
            policies=[
                ReadOnlyPolicy(assessment_permissions()),
                HeadersPolicy(),
                UserAgentPolicy(sdk_moniker="cloud-vuln-scan"),
                RetryPolicy(retry_total=3),
                BearerTokenCredentialPolicy(credential, ARM_SCOPE),
            ],
        )

    def _send(self, request: HttpRequest) -> dict[str, Any]:
        response = self._client.send_request(request)
        if response.status_code >= 400:
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)
        return response.json()

    def get(self, path: str, api_version: str) -> dict[str, Any]:
        return self._send(
            HttpRequest("GET", f"https://{ARM_HOST}{path}", params={"api-version": api_version})
        )

    def list(self, path: str, api_version: str, max_pages: int = 100) -> list[dict[str, Any]]:
        """All items of an ARM list, following "nextLink" pages. Each next page is a
        full URL from Azure; it still passes through the guard (host, GET, allowlist)."""
        body = self.get(path, api_version)
        items = list(body.get("value", []))
        for _ in range(max_pages):
            next_link = body.get("nextLink")
            if not next_link:
                return items
            body = self._send(HttpRequest("GET", next_link))
            items += body.get("value", [])
        raise RuntimeError(f"too many pages listing {path}")

    def subscription(self, subscription_id: str) -> dict[str, Any]:
        """{"subscriptionId", "tenantId", "displayName", "state", ...}"""
        return self.get(f"/subscriptions/{subscription_id}", SUBSCRIPTIONS_API_VERSION)
