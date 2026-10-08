"""JSON and CSV renderers for an AssessmentReport.

CSV injection: cloud resource names, tags and descriptions are controlled by the
client (or by an attacker inside the client's account). Spreadsheet programs treat a
cell starting with =, +, -, @, tab or carriage return as a FORMULA, which can run
commands or leak data when the consultant opens the file. Every such cell is
prefixed with a single quote so it is always displayed as plain text (OWASP
guidance). This is applied to every cell, not only to "risky-looking" columns.
"""

import csv
import io
import json

from app.domain.enums import Framework
from app.domain.findings import FrameworkRef
from app.reporting.report import AssessmentReport, ReportFinding

_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")

CSV_COLUMNS = (
    "finding_id",
    "severity",
    "rule_id",
    "title",
    "category",
    "provider",
    "account_id",
    "region",
    "resource_type",
    "resource_name",
    "resource_id",
    "detail",
    "risk",
    "recommendation",
    "cis",
    "nist_csf",
    "soc2",
    "evidence",
    "evidence_source",
    "detected_at",
    "review_status",
    "original_severity",
    "review_justification",
    "reviewed_by",
    "report_status",
    "client",
    "assessment",
    "scan_id",
)


def neutralize_formula(value: str) -> str:
    """Make a spreadsheet show this cell as text, never evaluate it."""
    return f"'{value}" if value.startswith(_FORMULA_TRIGGERS) else value


def _refs(refs: tuple[FrameworkRef, ...], *frameworks: Framework) -> str:
    return "; ".join(
        f"{r.control_id}{'' if r.verified else ' (unverified)'}"
        for r in refs
        if r.framework in frameworks
    )


def _row(finding: ReportFinding, report: AssessmentReport) -> list[str]:
    values = {
        "finding_id": finding.finding_id,
        "severity": finding.severity.value,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "category": finding.category.value,
        "provider": finding.provider.value,
        "account_id": finding.account_id,
        "region": finding.region or "account-wide",
        "resource_type": finding.resource_type or "",
        "resource_name": finding.resource_name or "(account)",
        "resource_id": finding.resource_id or "",
        "detail": finding.message,
        "risk": finding.risk,
        "recommendation": finding.recommendation,
        "cis": _refs(finding.framework_refs, Framework.CIS_AWS, Framework.CIS_AZURE),
        "nist_csf": _refs(finding.framework_refs, Framework.NIST_CSF),
        "soc2": _refs(finding.framework_refs, Framework.SOC2),
        "evidence": " | ".join(e.summary for e in finding.evidence),
        "evidence_source": " | ".join(e.source_operation for e in finding.evidence),
        "detected_at": finding.detected_at.isoformat(),
        "review_status": finding.review.status,
        "original_severity": finding.review.original_severity.value,
        "review_justification": finding.review.justification or "",
        "reviewed_by": finding.review.reviewed_by or "",
        "report_status": report.source.report_status,
        "client": report.source.client_name,
        "assessment": report.source.assessment_name,
        "scan_id": str(report.source.scan_id),
    }
    return [neutralize_formula(values[column]) for column in CSV_COLUMNS]


def to_csv(report: AssessmentReport) -> bytes:
    """One row per finding: reported findings (most severe first), then accepted
    risks, then false positives; the review_status column tells them apart. UTF-8
    with a byte-order mark, which Excel on Windows needs for non-English characters."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for findings in (report.findings, report.accepted_risks, report.false_positives):
        writer.writerows(_row(finding, report) for finding in findings)
    return buffer.getvalue().encode("utf-8-sig")


def to_json(report: AssessmentReport) -> bytes:
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False).encode("utf-8")
