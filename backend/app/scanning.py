"""Run a complete assessment of one cloud account: connect, verify, collect, evaluate.

This is the single entry point the CLI uses now and the background worker will use
later (M8), so both follow exactly the same safe sequence.
"""

import logging
from typing import Any

from app.core.config import Settings
from app.domain.findings import AssessmentResult
from app.providers.aws import collectors as aws_collectors
from app.providers.aws.session import CLIENT_CONFIG, AwsConnection, assume_assessment_role
from app.providers.azure import collectors as azure_collectors
from app.providers.azure.arm import ArmReader
from app.providers.azure.session import AzureConnection, platform_credential
from app.rules.engine import RuleEngine

logger = logging.getLogger(__name__)


class WrongAccountError(RuntimeError):
    """The credentials lead to a different account than the one being assessed."""


def scan_aws(
    connection: AwsConnection,
    settings: Settings,
    regions: list[str] | None = None,
    session: Any | None = None,
    engine: RuleEngine | None = None,
) -> AssessmentResult:
    session = session or assume_assessment_role(connection, settings)

    # Never collect anything before confirming we are in the intended client account.
    actual = session.client("sts", config=CLIENT_CONFIG).get_caller_identity()["Account"]
    if actual != connection.account_id:
        raise WrongAccountError(f"expected account {connection.account_id}, got {actual}")

    inventory = aws_collectors.collect_inventory(
        session, connection.account_id, settings.aws_region, regions
    )
    result = (engine or RuleEngine()).run(inventory)
    logger.info(
        "aws assessment completed",
        extra={"account_id": connection.account_id, "findings": len(result.findings)},
    )
    return result


def scan_azure(
    connection: AzureConnection,
    settings: Settings,
    regions: list[str] | None = None,
    credential: Any | None = None,
    engine: RuleEngine | None = None,
) -> AssessmentResult:
    credential = credential or platform_credential(connection, settings)

    # Never collect anything before confirming the subscription belongs to the
    # expected tenant and is enabled. Fails closed: missing values are a mismatch.
    subscription = ArmReader(credential).subscription(connection.subscription_id)
    tenant = str(subscription.get("tenantId") or "").lower()
    if tenant != connection.tenant_id.lower():
        raise WrongAccountError(
            f"subscription {connection.subscription_id} belongs to tenant "
            f"{tenant or 'unknown'}, expected {connection.tenant_id}"
        )
    if str(subscription.get("state") or "").lower() != "enabled":
        raise WrongAccountError(f"subscription {connection.subscription_id} is not enabled")

    inventory = azure_collectors.collect_inventory(credential, connection.subscription_id, regions)
    result = (engine or RuleEngine()).run(inventory)
    logger.info(
        "azure assessment completed",
        extra={"subscription_id": connection.subscription_id, "findings": len(result.findings)},
    )
    return result
