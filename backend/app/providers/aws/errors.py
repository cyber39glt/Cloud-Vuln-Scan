"""Turn AWS SDK errors into plain-language problems a consultant can act on.

Raw AWS error text is never shown or stored as-is: it is redacted, and the
consultant gets a fixed explanation plus a hint about what to check.
"""

from dataclasses import dataclass

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
)

from app.core.logging import redact_text
from app.providers.aws.guard import ReadOnlyViolation


@dataclass(frozen=True)
class AwsProblem:
    code: str
    message: str
    hint: str


_CLIENT_ERRORS = {
    "AccessDenied": (
        "AWS denied the request.",
        "For role access: check the role exists in the client account, trusts the "
        "platform identity, and uses exactly the ExternalId from the setup instructions. "
        "For other calls: the role may be missing a read permission.",
    ),
    "AccessDeniedException": (
        "AWS denied the request.",
        "The assessment role is missing a read permission for this service.",
    ),
    "UnauthorizedOperation": (
        "AWS denied the request.",
        "The assessment role is missing a read permission for this service.",
    ),
    "InvalidClientTokenId": (
        "The platform's AWS credentials are not valid.",
        "Check the platform access key (AWS_ACCESS_KEY_ID) is correct and active.",
    ),
    "SignatureDoesNotMatch": (
        "The platform's AWS secret key is wrong.",
        "Check AWS_SECRET_ACCESS_KEY matches the access key.",
    ),
    "ExpiredToken": (
        "The temporary AWS credentials have expired.",
        "Start a new session; credentials last at most one hour.",
    ),
    "RegionDisabledException": (
        "The AWS region is not enabled in this account.",
        "Enable the region, or ignore it if it is not in assessment scope.",
    ),
}


def describe_aws_error(error: Exception) -> AwsProblem:
    if isinstance(error, ReadOnlyViolation):
        return AwsProblem("ReadOnlyViolation", str(error), "This is a platform safeguard.")
    if isinstance(error, NoCredentialsError | PartialCredentialsError):
        return AwsProblem(
            "NoPlatformCredentials",
            "The platform has no AWS identity configured.",
            "Locally: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env "
            "(see docs/aws-connection.md).",
        )
    if isinstance(error, EndpointConnectionError):
        return AwsProblem(
            "NetworkError",
            "Could not reach AWS.",
            "Check internet access and that the region name is correct.",
        )
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message, hint = _CLIENT_ERRORS.get(
            code,
            ("AWS returned an error.", redact_text(str(error.response.get("Error", {})))),
        )
        return AwsProblem(code, message, hint)
    if isinstance(error, BotoCoreError):
        return AwsProblem(type(error).__name__, "The AWS SDK reported an error.", "")
    return AwsProblem(type(error).__name__, "Unexpected error.", "")
