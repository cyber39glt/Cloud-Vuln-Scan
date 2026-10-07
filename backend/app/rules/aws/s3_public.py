"""AWS-STO-001 / AWS-STO-002: S3 public access."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

_FLAGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)


class S3AccountBlockPublicAccessOff(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-STO-001",
        title="S3 account-level Block Public Access is not fully enabled",
        category=Category.STORAGE,
        severity=Severity.MEDIUM,
        scope="account",
        description="One or more of the four account-wide S3 Block Public Access settings is off.",
        risk=(
            "Account-level Block Public Access is a safety net: with it fully on, a single "
            "mistaken bucket policy or ACL cannot expose data to the internet."
        ),
        recommendation=(
            "Turn on all four Block Public Access settings at the account level, and grant "
            "exceptions only for buckets that genuinely must be public (e.g. via CloudFront)."
        ),
        required_resource_types={Provider.AWS: ("aws.s3.account_settings",)},
        required_permissions={Provider.AWS: ("s3:GetAccountPublicAccessBlock",)},
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for settings in self.resources(inventory):
            off = [flag for flag in _FLAGS if not settings.properties.get(flag)]
            if not off:
                yield self.passed(inventory, "All four account-level settings are on.")
                continue
            yield self.failed(
                inventory,
                f"{len(off)} of 4 account-level Block Public Access settings are off.",
                [self.evidence(settings, f"Off: {', '.join(off)}.", dict(settings.properties))],
            )


class S3BucketPublic(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-STO-002",
        title="S3 bucket is publicly accessible",
        category=Category.STORAGE,
        severity=Severity.HIGH,
        scope="resource",
        description=(
            "A bucket policy or ACL grants access to everyone, and Block Public Access "
            "(bucket or account level) does not neutralize it."
        ),
        risk=(
            "Anyone on the internet may be able to read (or write) objects in the bucket. "
            "Public buckets are a leading cause of large data leaks."
        ),
        recommendation=(
            "Remove public grants from the bucket policy and ACL, enable Block Public "
            "Access, and serve genuinely public content through CloudFront with an origin "
            "access control instead."
        ),
        required_resource_types={Provider.AWS: ("aws.s3.bucket", "aws.s3.account_settings")},
        required_permissions={
            Provider.AWS: (
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketAcl",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetAccountPublicAccessBlock",
            )
        },
        limitations=(
            "Relies on AWS's own analysis of the bucket policy (PolicyStatus.IsPublic). "
            "Access points and cross-account grants to specific accounts are not assessed.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        account = next(iter(inventory.of_type("aws.s3.account_settings")), None)
        account_flags = account.properties if account else {}
        for bucket in inventory.of_type("aws.s3.bucket"):
            props = bucket.properties

            def blocked(flag: str, props: dict = props) -> bool:
                return bool(props.get(flag)) or bool(account_flags.get(flag))

            exposures = []
            if props.get("policy_public") and not blocked("restrict_public_buckets"):
                exposures.append("bucket policy")
            if props.get("acl_public") and not blocked("ignore_public_acls"):
                exposures.append("ACL")
            if not exposures:
                yield self.passed(bucket, "Not publicly accessible.")
                continue
            yield self.failed(
                bucket,
                f"Public through its {' and '.join(exposures)}.",
                [
                    self.evidence(
                        bucket,
                        f"Public via {' and '.join(exposures)}; "
                        "Block Public Access does not prevent it.",
                        {
                            "policy_public": props.get("policy_public"),
                            "acl_public": props.get("acl_public"),
                            "bucket_block_public_access": {f: props.get(f) for f in _FLAGS},
                            "account_block_public_access": {
                                f: account_flags.get(f) for f in _FLAGS
                            },
                        },
                    )
                ],
            )
