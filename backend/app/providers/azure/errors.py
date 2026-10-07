"""Turn Azure SDK errors into plain-language problems a consultant can act on.

Entra ID sign-in errors carry an "AADSTS" code; Azure Resource Manager errors carry
an HTTP status and an error code. Raw error text is never shown as-is.
"""

import re
from dataclasses import dataclass

from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ServiceRequestError,
)

from app.core.logging import redact_text
from app.providers.azure.session import AzurePlatformNotConfigured
from app.providers.common import ReadOnlyViolation


@dataclass(frozen=True)
class AzureProblem:
    code: str
    message: str
    hint: str


# Entra ID sign-in error codes (https://login.microsoftonline.com/error).
_SIGN_IN_ERRORS = {
    "AADSTS700016": (
        "The platform app is not present in the client's tenant.",
        "The client's administrator must open the admin consent link first "
        "(see docs/azure-connection.md, 'Client onboarding').",
    ),
    "AADSTS7000215": (
        "The platform app's client secret is wrong.",
        "Check AZURE_CLIENT_SECRET in .env.",
    ),
    "AADSTS7000222": (
        "The platform app's client secret has expired.",
        "Create a new client secret for the app and update AZURE_CLIENT_SECRET.",
    ),
    "AADSTS90002": (
        "The tenant ID was not found.",
        "Check the client's tenant (directory) ID.",
    ),
    "AADSTS900023": (
        "The tenant ID is not valid.",
        "Check the client's tenant (directory) ID.",
    ),
}

_ARM_ERRORS = {
    "AuthorizationFailed": (
        "Azure denied the request.",
        "The platform app lacks the Reader / Security Reader role on this subscription.",
    ),
    "SubscriptionNotFound": (
        "The subscription was not found or is not visible to the platform.",
        "Check the subscription ID and that the roles were assigned on THIS subscription.",
    ),
    "InvalidAuthenticationTokenTenant": (
        "The subscription belongs to a different tenant.",
        "Check that the tenant ID and subscription ID belong together.",
    ),
}


def describe_azure_error(error: Exception) -> AzureProblem:
    if isinstance(error, ReadOnlyViolation):
        return AzureProblem("ReadOnlyViolation", str(error), "This is a platform safeguard.")
    if isinstance(error, AzurePlatformNotConfigured):
        return AzureProblem("NoPlatformCredentials", str(error), "")
    if isinstance(error, ClientAuthenticationError):
        match = re.search(r"AADSTS\d+", str(error))
        code = match.group(0) if match else "AuthenticationFailed"
        message, hint = _SIGN_IN_ERRORS.get(
            code, ("Sign-in to the client's tenant failed.", f"Entra ID error {code}.")
        )
        return AzureProblem(code, message, hint)
    if isinstance(error, ServiceRequestError):
        return AzureProblem("NetworkError", "Could not reach Azure.", "Check internet access.")
    if isinstance(error, HttpResponseError):
        code = (getattr(error, "error", None) and error.error.code) or str(error.status_code)
        message, hint = _ARM_ERRORS.get(
            code,
            ("Azure returned an error.", redact_text(f"HTTP {error.status_code} {code}")),
        )
        if code not in _ARM_ERRORS and error.status_code == 403:
            message, hint = _ARM_ERRORS["AuthorizationFailed"]
        return AzureProblem(code, message, hint)
    return AzureProblem(type(error).__name__, "Unexpected error.", "")
