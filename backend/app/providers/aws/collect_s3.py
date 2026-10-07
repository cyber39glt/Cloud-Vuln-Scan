"""AWS S3 collection: account-level Block Public Access and, per bucket, whether its
policy or ACL makes it public and which Block Public Access settings apply.

API calls: s3control:GetPublicAccessBlock (IAM: s3:GetAccountPublicAccessBlock),
s3:ListBuckets (IAM: s3:ListAllMyBuckets), s3:GetBucketLocation,
s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetPublicAccessBlock
(IAM: s3:GetBucketPublicAccessBlock).

Never read: bucket contents, object lists, or the policy document itself. AWS's own
policy analysis (GetBucketPolicyStatus -> IsPublic) is used instead.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

from app.domain.enums import Provider
from app.domain.inventory import CollectionGap, Resource
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.session import CLIENT_CONFIG
from app.providers.common import ReadOnlyViolation

S3_ACCOUNT = "aws.s3.account_settings"
S3_BUCKET = "aws.s3.bucket"

PUBLIC_GRANTEES = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)
_BLOCK_FLAGS = {
    "BlockPublicAcls": "block_public_acls",
    "IgnorePublicAcls": "ignore_public_acls",
    "BlockPublicPolicy": "block_public_policy",
    "RestrictPublicBuckets": "restrict_public_buckets",
}
_NOT_CONFIGURED = "NoSuchPublicAccessBlockConfiguration"


class PolicyStatusUnavailable(RuntimeError):
    """AWS did not report whether the bucket policy is public."""


def _error_code(error: ClientError) -> str:
    return error.response.get("Error", {}).get("Code", "")


def _block_settings(call: Callable[[], dict[str, Any]]) -> dict[str, bool]:
    """Block Public Access flags; "not configured" means every flag is off."""
    try:
        config = call()["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _error_code(exc) != _NOT_CONFIGURED:
            raise
        config = {}
    return {name: bool(config.get(key, False)) for key, name in _BLOCK_FLAGS.items()}


def _bucket(
    s3_for: Callable[[str], Any], raw: dict[str, Any], account_id: str, collected_at: datetime
) -> Resource:
    name = raw["Name"]
    location = s3_for("us-east-1").get_bucket_location(Bucket=name).get("LocationConstraint")
    region = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(location, location)
    s3 = s3_for(region)

    try:
        status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
        if "IsPublic" not in status:
            raise PolicyStatusUnavailable(name)
        policy_public = bool(status["IsPublic"])
    except ClientError as exc:
        if _error_code(exc) != "NoSuchBucketPolicy":
            raise
        policy_public = False  # no bucket policy at all

    grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
    acl_public = any(g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES for g in grants)
    block = _block_settings(lambda: s3.get_public_access_block(Bucket=name))
    return Resource(
        provider=Provider.AWS,
        account_id=account_id,
        region=region,
        resource_type=S3_BUCKET,
        resource_id=f"arn:aws:s3:::{name}",
        name=name,
        properties={"policy_public": policy_public, "acl_public": acl_public, **block},
        source_operation="s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetPublicAccessBlock",
        collected_at=collected_at,
    )


def collect_s3(
    session: Any, account_id: str, scope: list[str] | None, collected_at: datetime
) -> tuple[list[Resource], list[CollectionGap]]:
    resources: list[Resource] = []
    gaps: list[CollectionGap] = []
    clients: dict[str, Any] = {}

    def s3_for(region: str) -> Any:
        if region not in clients:
            clients[region] = session.client("s3", region_name=region, config=CLIENT_CONFIG)
        return clients[region]

    # Account-level Block Public Access (S3 Control API).
    try:
        control = session.client("s3control", region_name="us-east-1", config=CLIENT_CONFIG)
        settings = _block_settings(lambda: control.get_public_access_block(AccountId=account_id))
        resources.append(
            Resource(
                provider=Provider.AWS,
                account_id=account_id,
                region="global",
                resource_type=S3_ACCOUNT,
                resource_id=f"arn:aws:s3:::account/{account_id}",
                name="S3 account settings",
                properties=settings,
                source_operation="s3:GetAccountPublicAccessBlock",
                collected_at=collected_at,
            )
        )
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        gaps.append(CollectionGap(resource_type=S3_ACCOUNT, reason=describe_aws_error(exc).code))

    # Buckets (the list is global; each bucket lives in one region).
    try:
        buckets = s3_for("us-east-1").list_buckets().get("Buckets", [])
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        return resources, [
            *gaps,
            CollectionGap(resource_type=S3_BUCKET, reason=describe_aws_error(exc).code),
        ]

    for raw in buckets:
        try:
            bucket = _bucket(s3_for, raw, account_id, collected_at)
        except ReadOnlyViolation:
            raise
        except PolicyStatusUnavailable:
            gaps.append(
                CollectionGap(
                    resource_type=S3_BUCKET,
                    reason=f"bucket {raw['Name']}: policy status not reported",
                )
            )
            continue
        except Exception as exc:
            gaps.append(
                CollectionGap(
                    resource_type=S3_BUCKET,
                    reason=f"bucket {raw['Name']}: {describe_aws_error(exc).code}",
                )
            )
            continue
        if scope is None or bucket.region in scope:
            resources.append(bucket)
    return resources, gaps
