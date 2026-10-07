"""AWS RDS collection: database instances and whether they are publicly accessible.

API call: rds:DescribeDBInstances (per region in scope). Kept per instance:
identifier, engine, publicly accessible. Nothing about data, users or passwords.
"""

from datetime import datetime
from typing import Any

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Resource
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.session import CLIENT_CONFIG
from app.providers.common import ReadOnlyViolation

RDS_INSTANCE = "aws.rds.db_instance"


def collect_rds(
    session: Any, account_id: str, regions: list[str], collected_at: datetime
) -> tuple[list[Resource], list[CollectionGap]]:
    resources: list[Resource] = []
    gaps: list[CollectionGap] = []
    for region in regions:
        try:
            rds = session.client("rds", region_name=region, config=CLIENT_CONFIG)
            for page in rds.get_paginator("describe_db_instances").paginate():
                resources += [
                    Resource(
                        provider=Provider.AWS,
                        account_id=account_id,
                        region=region,
                        resource_type=RDS_INSTANCE,
                        resource_id=raw["DBInstanceArn"],
                        name=raw["DBInstanceIdentifier"],
                        properties={
                            "engine": raw.get("Engine"),
                            "publicly_accessible": bool(raw.get("PubliclyAccessible")),
                        },
                        source_operation="rds:DescribeDBInstances",
                        collected_at=collected_at,
                    )
                    for raw in page.get("DBInstances", [])
                ]
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            gaps.append(
                CollectionGap(
                    resource_type=RDS_INSTANCE, region=region, reason=describe_aws_error(exc).code
                )
            )
    return resources, gaps
