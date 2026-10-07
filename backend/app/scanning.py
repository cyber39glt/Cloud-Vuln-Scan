"""Run a complete assessment of one cloud account: connect, verify, collect, evaluate.

This is the single entry point the CLI uses now and the background worker will use
later (M8), so both follow exactly the same safe sequence.
"""

import logging
from typing import Any

from app.core.config import Settings
from app.domain.findings import AssessmentResult
from app.providers.aws.collectors import collect_inventory
from app.providers.aws.session import CLIENT_CONFIG, AwsConnection, assume_assessment_role
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

    inventory = collect_inventory(session, connection.account_id, settings.aws_region, regions)
    result = (engine or RuleEngine()).run(inventory)
    logger.info(
        "aws assessment completed",
        extra={"account_id": connection.account_id, "findings": len(result.findings)},
    )
    return result
