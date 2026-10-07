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

    def get(self, path: str, api_version: str) -> dict[str, Any]:
        request = HttpRequest(
            "GET", f"https://{ARM_HOST}{path}", params={"api-version": api_version}
        )
        response = self._client.send_request(request)
        if response.status_code >= 400:
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)
        return response.json()

    def subscription(self, subscription_id: str) -> dict[str, Any]:
        """{"subscriptionId", "tenantId", "displayName", "state", ...}"""
        return self.get(f"/subscriptions/{subscription_id}", SUBSCRIPTIONS_API_VERSION)
