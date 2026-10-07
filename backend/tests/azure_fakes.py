"""Shared test doubles for Azure: no real tokens, tenants or network."""

import re
import time

from azure.core.credentials import AccessToken, AccessTokenInfo

TENANT = "22222222-2222-2222-2222-222222222222"
SUB = "11111111-1111-1111-1111-111111111111"
ARM = "https://management.azure.com"


class FakeCredential:
    """Stands in for an Entra ID token; nothing leaves the test process."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    def get_token(self, *_, **__):
        if self.error:
            raise self.error
        return AccessToken("fake-token", int(time.time()) + 3600)

    def get_token_info(self, *_, **__):
        if self.error:
            raise self.error
        return AccessTokenInfo("fake-token", int(time.time()) + 3600)


def arm_url(path: str) -> re.Pattern[str]:
    """Match an ARM URL for `path`, with any query string (api-version etc.)."""
    return re.compile(re.escape(f"{ARM}{path}") + r"\?.*")


def mock_subscription(rsps, tenant: str | None = TENANT, state: str | None = "Enabled") -> None:
    body = {"subscriptionId": SUB, "displayName": "Sandbox"}
    if tenant is not None:
        body["tenantId"] = tenant
    if state is not None:
        body["state"] = state
    rsps.get(arm_url(f"/subscriptions/{SUB}"), json=body)
