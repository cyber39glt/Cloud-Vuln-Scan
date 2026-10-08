"""Results of an assessment: check results, evidence, findings.

One `AssessmentResult` is the single dataset that will later feed the dashboard,
PDF, CSV and JSON outputs (ADR 0007).
"""

import hashlib
from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.logging import redact_text, redact_value
from app.domain.enums import Category, CheckStatus, Framework, Provider, Severity


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Evidence(_Frozen):
    """Proof behind a result: where the data came from and the exact fields observed.

    Values are redacted on creation, so a secret that slipped into collected data
    cannot reach a report through evidence.
    """

    source_operation: str
    collected_at: datetime
    summary: str
    observed: dict[str, Any] = Field(default_factory=dict)

    @field_validator("summary")
    @classmethod
    def _redact_summary(cls, value: str) -> str:
        return redact_text(value)

    @field_validator("observed")
    @classmethod
    def _redact_observed(cls, value: dict[str, Any]) -> dict[str, Any]:
        return redact_value(value)


class CheckResult(_Frozen):
    """The outcome of one rule for one resource (or for the whole account)."""

    rule_id: str
    provider: Provider
    account_id: str
    status: CheckStatus
    message: str
    # Resource fields are None for account-level results (e.g. "no CloudTrail at all").
    resource_id: str | None = None
    resource_name: str | None = None
    resource_type: str | None = None
    region: str | None = None
    evidence: tuple[Evidence, ...] = ()

    @field_validator("message")
    @classmethod
    def _redact_message(cls, value: str) -> str:
        return redact_text(value)


class FrameworkRef(_Frozen):
    framework: Framework
    framework_name: str
    version: str
    control_id: str
    title: str
    # False until a person has checked the reference against the official source.
    verified: bool


class Finding(_Frozen):
    """A security weakness: a FAIL result enriched with the rule's explanation."""

    finding_id: str
    rule_id: str
    rule_version: int
    title: str
    provider: Provider
    account_id: str
    category: Category
    severity: Severity
    resource_id: str | None
    resource_name: str | None
    resource_type: str | None
    region: str | None
    message: str
    description: str
    risk: str
    recommendation: str
    evidence: tuple[Evidence, ...]
    framework_refs: tuple[FrameworkRef, ...]
    detected_at: datetime


def finding_fingerprint(
    rule_id: str, provider: Provider, account_id: str, resource_id: str | None
) -> str:
    """Stable ID: the same weakness on the same resource always gets the same ID,
    so it can be recognized across assessments (new / still present / resolved)."""
    key = "|".join([rule_id, provider.value, account_id, resource_id or "<account>"])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


class RuleRun(_Frozen):
    rule_id: str
    rule_version: int


class AssessmentResult(_Frozen):
    provider: Provider
    account_id: str
    engine_version: str
    regions: tuple[str, ...] = ()  # assessment scope (regions collected)
    started_at: datetime
    completed_at: datetime
    rules_run: tuple[RuleRun, ...]
    results: tuple[CheckResult, ...]
    findings: tuple[Finding, ...]

    def status_counts(self) -> dict[CheckStatus, int]:
        counts = Counter(r.status for r in self.results)
        return {status: counts.get(status, 0) for status in CheckStatus}

    def severity_counts(self) -> dict[Severity, int]:
        counts = Counter(f.severity for f in self.findings)
        return {severity: counts.get(severity, 0) for severity in Severity}
