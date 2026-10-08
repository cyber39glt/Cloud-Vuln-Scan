"""The report dataset: everything an output needs, built once from a stored scan.

    stored scan (hash-verified AssessmentResult) + review decisions + metadata
        └─► AssessmentReport ─► dashboard / PDF / JSON / CSV

Reviews (ADR 0007, ADR 0023) never change the stored scan. They are applied here:
findings get their effective severity and review details; false positives and
accepted risks are moved to their own lists, so they never inflate the totals.
A FINALIZED assessment's report is not rebuilt: it is read back from the frozen,
hash-verified snapshot taken at finalization.

The JSON export IS this model, serialized. Its structure is versioned
(REPORT_SCHEMA_VERSION) and published as a JSON Schema for integrations.
"""

import hmac
import uuid
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.enums import Category, CheckStatus, Provider, Severity
from app.domain.findings import AssessmentResult, CheckResult, Finding
from app.domain.reviews import Review
from app.storage import repository as repo
from app.storage import reviews
from app.storage.models import Assessment, AssessmentStatus, Client, ScanRun

# Increase the minor version for additions, the major version for breaking changes.
# 1.1: review details on findings, accepted_risks / false_positives lists, report status.
REPORT_SCHEMA_VERSION = "1.1"

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
    # "final" only for the frozen snapshot of a finalized assessment; else "draft".
    report_status: Literal["draft", "final"] = "draft"
    finalized_at: datetime | None = None
    finalized_by: str | None = None


class FindingReviewInfo(_Frozen):
    status: str = "open"
    original_severity: Severity
    severity_overridden: bool = False
    justification: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None


class ReportFinding(Finding):
    """A finding as reported: `severity` is the EFFECTIVE severity (after any
    override); the scanner's original severity is in `review.original_severity`."""

    review: FindingReviewInfo


class RuleGroup(_Frozen):
    """Findings grouped by rule for display, e.g. 'SSH open to the internet: 7'."""

    rule_id: str
    title: str
    severity: Severity
    affected_resources: int


class ReportSummary(_Frozen):
    # Reported findings only (open and confirmed); see by_review_status for all.
    total_findings: int
    by_severity: dict[Severity, int]
    by_category: dict[Category, int]
    by_rule: tuple[RuleGroup, ...]
    checks_by_status: dict[CheckStatus, int]
    rules_run: int
    by_review_status: dict[str, int] = {}


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
    findings: tuple[ReportFinding, ...]
    accepted_risks: tuple[ReportFinding, ...] = ()
    false_positives: tuple[ReportFinding, ...] = ()
    not_evaluated: tuple[NotEvaluated, ...]
    check_results: tuple[CheckResult, ...]
    notes: tuple[str, ...] = STANDARD_NOTES


def _apply_review(finding: Finding, review: Review | None) -> ReportFinding:
    info = FindingReviewInfo(original_severity=finding.severity)
    severity = finding.severity
    if review is not None:
        severity = review.severity_override or finding.severity
        info = FindingReviewInfo(
            status=review.status,
            original_severity=finding.severity,
            severity_overridden=review.severity_override is not None,
            justification=review.justification,
            reviewed_by=review.reviewed_by,
            reviewed_at=review.reviewed_at,
        )
    return ReportFinding(**finding.model_dump(), review=info).model_copy(
        update={"severity": severity}
    )


def _ordered(findings: list[ReportFinding]) -> tuple[ReportFinding, ...]:
    return tuple(
        sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.resource_name or ""))
    )


def build_report(
    result: AssessmentResult,
    source: ReportSource,
    generated_at: datetime | None = None,
    *,
    reviews: Mapping[str, Review] | None = None,
) -> AssessmentReport:
    """Pure function: same inputs, same report. No database, no network.
    `reviews` maps a finding's fingerprint (finding_id) to its review decision."""
    reviews = reviews or {}
    reviewed = [_apply_review(f, reviews.get(f.finding_id)) for f in result.findings]
    reported = _ordered([f for f in reviewed if f.review.status in ("open", "confirmed")])
    accepted = _ordered([f for f in reviewed if f.review.status == "accepted_risk"])
    false_positives = _ordered([f for f in reviewed if f.review.status == "false_positive"])

    by_rule: dict[str, list[ReportFinding]] = {}
    for finding in reported:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    categories = Counter(f.category for f in reported)
    severities = Counter(f.severity for f in reported)
    summary = ReportSummary(
        total_findings=len(reported),
        by_severity={s: severities.get(s, 0) for s in Severity},
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
        by_review_status=dict(Counter(f.review.status for f in reviewed)),
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
        findings=reported,
        accepted_risks=accepted,
        false_positives=false_positives,
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
    """The report for a stored scan. Client-scoped and hash-verified: another client's
    scan is NotFound; a tampered scan or snapshot raises IntegrityViolation.

    For the scan a finalized assessment was finalized on, the frozen snapshot is
    returned (exactly what was delivered). Otherwise a DRAFT is built with the
    current review decisions."""
    result = repo.load_scan_result(session, client_id, scan_id)
    scan, assessment, client = session.execute(
        select(ScanRun, Assessment, Client)
        .join(Assessment, Assessment.id == ScanRun.assessment_id)
        .join(Client, Client.id == ScanRun.client_id)
        .where(ScanRun.id == scan_id, ScanRun.client_id == client_id)
    ).one()

    final = reviews.current_finalization(session, client_id, assessment.id)
    if final is None and assessment.status == AssessmentStatus.FINALIZED:
        # A finalized assessment always has a snapshot. Its absence means the stored
        # data was tampered with: refuse rather than quietly serve a draft.
        raise repo.IntegrityViolation("finalized assessment has no finalized report")
    if final is not None and final.scan_run_id == scan.id:
        mac = reviews.finalization_mac(
            final.id, final.client_id, final.assessment_id, final.scan_run_id, final.report_sha256
        )
        if repo.result_hash(final.report) != final.report_sha256 or not hmac.compare_digest(
            final.report_mac or "", mac
        ):
            raise repo.IntegrityViolation("finalized report does not match its recorded hash")
        return AssessmentReport.model_validate(final.report)

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
        reviews=reviews.load_reviews(session, client_id, assessment.id),
    )
