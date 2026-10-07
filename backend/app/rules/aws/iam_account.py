"""AWS-IAM-005 / AWS-IAM-006: account-wide IAM settings."""

from collections.abc import Iterator

from app.domain.enums import Category, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import Inventory
from app.rules.base import Rule, RuleMetadata

MIN_PASSWORD_LENGTH = 14  # CIS AWS Foundations


class WeakPasswordPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-IAM-005",
        title="IAM password policy missing or too weak",
        category=Category.IDENTITY_ACCESS,
        severity=Severity.MEDIUM,
        scope="account",
        description=(
            f"The account has no IAM password policy, or it allows passwords shorter than "
            f"{MIN_PASSWORD_LENGTH} characters."
        ),
        risk="Short passwords are far easier to guess or crack.",
        recommendation=(
            f"Set an account password policy with a minimum length of at least "
            f"{MIN_PASSWORD_LENGTH} characters and password reuse prevention."
        ),
        required_resource_types={Provider.AWS: ("aws.iam.password_policy",)},
        required_permissions={Provider.AWS: ("iam:GetAccountPasswordPolicy",)},
        limitations=("Only relevant where IAM users sign in with passwords.",),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for policy in self.resources(inventory):
            props = policy.properties
            length = props.get("minimum_length") or 0
            if props.get("exists") and length >= MIN_PASSWORD_LENGTH:
                yield self.passed(inventory, f"Password policy requires {length}+ characters.")
                continue
            problem = (
                "No password policy is set."
                if not props.get("exists")
                else f"Minimum password length is {length} (below {MIN_PASSWORD_LENGTH})."
            )
            yield self.failed(inventory, problem, [self.evidence(policy, problem, props)])


class AdministratorAccessOnUsers(Rule):
    metadata = RuleMetadata(
        rule_id="AWS-IAM-006",
        title="AdministratorAccess attached to IAM users or groups",
        category=Category.IDENTITY_ACCESS,
        severity=Severity.MEDIUM,
        scope="account",
        description=(
            "The AWS-managed AdministratorAccess policy (full control of everything) is "
            "attached directly to IAM users or to IAM groups."
        ),
        risk=(
            "Every such user, and every key or password they hold, is a path to full "
            "control of the account. Standing administrator access multiplies the impact "
            "of any single compromised credential."
        ),
        recommendation=(
            "Grant administrator access only through roles assumed when needed (e.g. IAM "
            "Identity Center permission sets) and give users least-privilege permissions."
        ),
        required_resource_types={Provider.AWS: ("aws.iam.admin_policy",)},
        required_permissions={Provider.AWS: ("iam:ListEntitiesForPolicy",)},
        limitations=(
            "Only checks the AWS-managed AdministratorAccess policy, not custom policies "
            "granting equivalent rights. Roles with the policy are listed in evidence only.",
        ),
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        for policy in self.resources(inventory):
            users = policy.properties.get("users", [])
            groups = policy.properties.get("groups", [])
            if not users and not groups:
                yield self.passed(
                    inventory, "AdministratorAccess is not attached to users or groups."
                )
                continue
            yield self.failed(
                inventory,
                f"AdministratorAccess attached to {len(users)} user(s) and {len(groups)} group(s).",
                [
                    self.evidence(
                        policy,
                        "Entities with the AdministratorAccess policy attached.",
                        {
                            "users": users,
                            "groups": groups,
                            "roles": policy.properties.get("roles", []),
                        },
                    )
                ],
            )
