"""How the platform gets read-only access to a client's Azure subscription.

Flow (Microsoft Entra ID = Azure's identity service):

  platform app (client ID + its own credential)
      --"token for tenant <client tenant>, audience Azure Resource Manager"--> Entra ID
  Entra ID issues a short-lived token (about 1 hour) only if the client's admin has
      consented to the app in their tenant
  platform --GET requests with the token--> Azure Resource Manager
      Azure allows only what the client's role assignments permit (Reader + Security Reader)

The token is held in memory by azure-identity and never written to disk, logs or
the database. The platform stores only the tenant and subscription IDs.
"""

import re
from dataclasses import dataclass

from azure.identity import ClientSecretCredential

from app.core.config import Settings

GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
ARM_SCOPE = "https://management.azure.com/.default"
LOGIN_HOST = "login.microsoftonline.com"


class AzurePlatformNotConfigured(RuntimeError):
    """The platform's own Azure app identity is missing from the configuration."""


@dataclass(frozen=True)
class AzureConnection:
    tenant_id: str  # the client's Entra tenant (directory) ID
    subscription_id: str

    def __post_init__(self) -> None:
        if not GUID.fullmatch(self.tenant_id):
            raise ValueError("Azure tenant ID must be a GUID")
        if not GUID.fullmatch(self.subscription_id):
            raise ValueError("Azure subscription ID must be a GUID")


def platform_credential(connection: AzureConnection, settings: Settings) -> ClientSecretCredential:
    """A credential for the platform app, scoped to ONE client tenant."""
    secret = settings.azure_client_secret.get_secret_value()
    if not settings.azure_client_id or not secret:
        raise AzurePlatformNotConfigured(
            "The platform has no Azure identity configured. Locally: set AZURE_CLIENT_ID "
            "and AZURE_CLIENT_SECRET in .env (see docs/azure-connection.md)."
        )
    return ClientSecretCredential(
        tenant_id=connection.tenant_id,
        client_id=settings.azure_client_id,
        client_secret=secret,
        # Never fall back to other tenants, even if the app is registered elsewhere.
        additionally_allowed_tenants=[],
    )


def admin_consent_url(tenant_id: str, client_id: str) -> str:
    """The link a client's administrator opens once to let the app into their tenant.
    Consent creates the app's identity (service principal) in their directory; it
    grants no access to resources by itself."""
    return f"https://{LOGIN_HOST}/{tenant_id}/adminconsent?client_id={client_id}"
