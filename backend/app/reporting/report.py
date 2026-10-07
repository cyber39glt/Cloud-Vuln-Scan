"""The report dataset: everything an output needs, built once from a stored scan.

    stored scan (hash-verified AssessmentResult) + client/assessment metadata
        └─► AssessmentReport ─► JSON / CSV / (PDF, dashboard later)

The JSON export IS this model, serialized. Its structure is versioned
(REPORT_SCHEMA_VERSION) and published as a JSON Schema for integrations.
"""

import uuid
from collections import Counter
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.enums import Category, CheckStatus, Provider, Severity
from app.domain.findings import AssessmentResult, CheckResult, Finding
from app.storage import repository as repo
from app.storage.models import Assessment, Client, ScanRun

# Increase the minor version for additions, the major version for breaking changes.
REPORT_SCHEMA_VERSION = "1.0"

STANDARD_NOTES = (
    "This is a technical security assessment of cloud configuration at a point in time. "
    "It is not an audit and does not certify compliance with any framework.",
    "Framework references indicate controls a finding is relevant to; they do not state "
    "that a control is met or failed. References marked unverified have not yet been "
    "checked against the official framework document.",
    "Checks reported as 'not evaluated' could not be completed (for example because "
    "access was denied). Their absence from the findings does not mean the area is secure.",
)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReportSource(_Frozen):
    consultancy: str
    client_name: str
    assessment_id: uuid.UUID
    assessment_name: str
    assessment_status: str
    scan_id: uuid.UUID
    scan_sha256: str


class RuleGroup(_Frozen):
    """Findings grouped by rule for display, e.g. 'SSH open to the internet: 7'."""

    rule_id: str
    title: str
    severity: Severity
    affected_resources: int


class ReportSummary(_Frozen):
    total_findings: int
    by_severity: dict[Severity, int]
    by_category: dict[Category, int]
    by_rule: tuple[RuleGroup, ...]
    checks_by_status: dict[CheckStatus, int]
    rules_run: int


class NotEvaluated(_Frozen):
    rule_id: str
    region: str | None
    reason: str


class AssessmentReport(_Frozen):
    schema_version: str = REPORT_SCHEMA_VERSION
    generated_at: datetime
    source: ReportSource
    provider: Provider
    account_id: str
    regions: tuple[str, ...]
    engine_version: str
    scan_started_at: datetime
    scan_completed_at: datetime
    summary: ReportSummary
    findings: tuple[Finding, ...]
    not_evaluated: tuple[NotEvaluated, ...]
    check_results: tuple[CheckResult, ...]
    notes: tuple[str, ...] = STANDARD_NOTES


def build_report(
    result: AssessmentResult,
    source: ReportSource,
    generated_at: datetime | None = None,
) -> AssessmentReport:
    """Pure function: same inputs, same report. No database, no network."""
    by_rule: dict[str, list[Finding]] = {}
    for finding in result.findings:  # already sorted by severity, then rule
        by_rule.setdefault(finding.rule_id, []).append(finding)

    categories = Counter(f.category for f in result.findings)
    summary = ReportSummary(
        total_findings=len(result.findings),
        by_severity=result.severity_counts(),
        by_category={c: categories.get(c, 0) for c in Category},
        by_rule=tuple(
            RuleGroup(
                rule_id=rule_id,
                title=group[0].title,
                severity=group[0].severity,
                affected_resources=len(group),
            )
            for rule_id, group in by_rule.items()
        ),
        checks_by_status=result.status_counts(),
        rules_run=len(result.rules_run),
    )
    return AssessmentReport(
        generated_at=generated_at or datetime.now(UTC),
        source=source,
        provider=result.provider,
        account_id=result.account_id,
        regions=result.regions,
        engine_version=result.engine_version,
        scan_started_at=result.started_at,
        scan_completed_at=result.completed_at,
        summary=summary,
        findings=result.findings,
        not_evaluated=tuple(
            NotEvaluated(rule_id=r.rule_id, region=r.region, reason=r.message)
            for r in result.results
            if r.status == CheckStatus.ERROR
        ),
        check_results=result.results,
    )


def report_for_scan(
    session: Session, client_id: uuid.UUID, scan_id: uuid.UUID, consultancy: str
) -> AssessmentReport:
    """Build the report for a stored scan. Client-scoped and hash-verified:
    another client's scan is NotFound; a tampered scan raises IntegrityViolation."""
    result = repo.load_scan_result(session, client_id, scan_id)
    scan, assessment, client = session.execute(
        select(ScanRun, Assessment, Client)
        .join(Assessment, Assessment.id == ScanRun.assessment_id)
        .join(Client, Client.id == ScanRun.client_id)
        .where(ScanRun.id == scan_id, ScanRun.client_id == client_id)
    ).one()
    return build_report(
        result,
        ReportSource(
            consultancy=consultancy,
            client_name=client.name,
            assessment_id=assessment.id,
            assessment_name=assessment.name,
            assessment_status=assessment.status.value,
            scan_id=scan.id,
            scan_sha256=scan.result_sha256,
        ),
    )
