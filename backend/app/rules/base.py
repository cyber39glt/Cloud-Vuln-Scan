"""The building blocks every security rule uses.

A rule = metadata (what it checks and why) + `evaluate()` (how it decides).
See docs/rules.md for a step-by-step guide to writing one.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from typing import ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.enums import Category, CheckStatus, Provider, Severity
from app.domain.findings import CheckResult, Evidence
from app.domain.inventory import Inventory, Resource


class RuleMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # e.g. NET-001 (cross-cloud), AWS-LOG-001, AZ-STO-001
    rule_id: str = Field(pattern=r"^[A-Z]{2,5}(-[A-Z]{2,5})?-\d{3}$")
    # Increase when the rule's logic changes, so old results stay explainable.
    version: int = Field(default=1, ge=1)
    title: str = Field(min_length=1)
    category: Category
    severity: Severity  # Default severity; consultants may override with justification.
    # "resource": judges each resource separately.
    # "account": judges the account as a whole (e.g. "is there ANY multi-region trail?").
    scope: Literal["resource", "account"]
    description: str = Field(min_length=1)
    risk: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    # Which normalized resource types the rule reads, per provider. The keys define
    # which providers the rule supports.
    required_resource_types: dict[Provider, tuple[str, ...]]
    # The read-only permissions collectors need for this rule. Used to build
    # least-privilege client policies later (ADR 0002).
    required_permissions: dict[Provider, tuple[str, ...]]
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _providers_consistent(self) -> Self:
        if not self.required_resource_types:
            raise ValueError("a rule must support at least one provider")
        if set(self.required_resource_types) != set(self.required_permissions):
            raise ValueError("required_permissions must list the same providers as resource types")
        return self

    @property
    def providers(self) -> frozenset[Provider]:
        return frozenset(self.required_resource_types)


class Rule(ABC):
    metadata: ClassVar[RuleMetadata]

    @abstractmethod
    def evaluate(self, inventory: Inventory) -> Iterable[CheckResult]:
        """Yield one CheckResult per resource judged (or one for the account)."""

    def resources(self, inventory: Inventory) -> list[Resource]:
        """The in-scope resources of the types this rule declared for this provider."""
        return inventory.of_type(*self.metadata.required_resource_types[inventory.provider])

    # Helpers so rules read naturally: `yield self.failed(resource, "...", evidence)`.
    # `subject` is a Resource for resource-level results, or the Inventory for
    # account-level results.

    def passed(self, subject: Resource | Inventory, message: str) -> CheckResult:
        return self._result(CheckStatus.PASS, subject, message, ())

    def failed(
        self, subject: Resource | Inventory, message: str, evidence: Sequence[Evidence]
    ) -> CheckResult:
        if not evidence:
            raise ValueError("a failed check must include evidence")
        return self._result(CheckStatus.FAIL, subject, message, evidence)

    def _result(
        self,
        status: CheckStatus,
        subject: Resource | Inventory,
        message: str,
        evidence: Sequence[Evidence],
    ) -> CheckResult:
        resource = subject if isinstance(subject, Resource) else None
        return CheckResult(
            rule_id=self.metadata.rule_id,
            provider=subject.provider,
            account_id=subject.account_id,
            status=status,
            message=message,
            resource_id=resource.resource_id if resource else None,
            resource_name=resource.name if resource else None,
            resource_type=resource.resource_type if resource else None,
            region=resource.region if resource else None,
            evidence=tuple(evidence),
        )
