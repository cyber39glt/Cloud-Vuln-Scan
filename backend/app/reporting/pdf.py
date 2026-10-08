"""PDF renderer for an AssessmentReport (ADR 0004, ADR 0022).

    AssessmentReport (the single dataset) ─► view model ─► Jinja2 HTML ─► WeasyPrint ─► PDF

Safety: the report contains text controlled by the client (resource names, tags,
evidence), so
- the HTML template AUTO-ESCAPES every value: client text can never become markup;
- the renderer may not fetch ANYTHING: no network, no local files. Only `data:` URIs
  (inline resources we produce ourselves) are allowed. A blocked attempt is logged;
- nothing is written to disk: the PDF is returned as bytes.
"""

import json
import logging
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from app.domain.enums import Severity
from app.domain.findings import Finding
from app.reporting.report import AssessmentReport
from app.rules.registry import ALL_RULES

logger = logging.getLogger(__name__)

TEMPLATES = Path(__file__).with_name("templates")
SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
)
# Evidence is summarized in the PDF; the full data is in the JSON export.
MAX_EVIDENCE_CHARS = 1200
MAX_INSTANCES_WITH_EVIDENCE = 25

_environment = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
    undefined=StrictUndefined,  # a typo in the template fails loudly, not silently
    trim_blocks=True,
    lstrip_blocks=True,
)


# ------------------------------------------------------------------ view model


@dataclass
class Instance:
    resource: str
    region: str
    message: str
    resource_id: str | None
    evidence: list[dict[str, str]] = field(default_factory=list)


@dataclass
class FindingGroup:
    """All resources affected by one rule: one section in the report."""

    number: str
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    risk: str
    recommendation: str
    framework_refs: list[dict[str, Any]]
    instances: list[Instance]
    evidence_omitted: int


def _evidence_text(observed: dict[str, Any]) -> str:
    text = json.dumps(observed, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    if len(text) > MAX_EVIDENCE_CHARS:
        text = text[:MAX_EVIDENCE_CHARS] + "\n… (truncated; full evidence in the JSON export)"
    return text


def _groups(findings: tuple[Finding, ...]) -> list[FindingGroup]:
    by_rule: OrderedDict[str, list[Finding]] = OrderedDict()
    for finding in sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id)):
        by_rule.setdefault(finding.rule_id, []).append(finding)

    groups = []
    for index, (rule_id, items) in enumerate(by_rule.items(), start=1):
        first = items[0]
        instances = []
        for position, f in enumerate(items):
            instances.append(
                Instance(
                    resource=f.resource_name or "Account-wide",
                    region=f.region or "—",
                    message=f.message,
                    resource_id=f.resource_id,
                    evidence=[
                        {
                            "summary": e.summary,
                            "source": e.source_operation,
                            "observed": _evidence_text(e.observed) if e.observed else "",
                        }
                        for e in f.evidence
                    ]
                    if position < MAX_INSTANCES_WITH_EVIDENCE
                    else [],
                )
            )
        groups.append(
            FindingGroup(
                number=f"F-{index:02d}",
                rule_id=rule_id,
                title=first.title,
                severity=first.severity,
                category=first.category.value.replace("_", " ").capitalize(),
                description=first.description,
                risk=first.risk,
                recommendation=first.recommendation,
                framework_refs=[r.model_dump(mode="json") for r in first.framework_refs],
                instances=instances,
                evidence_omitted=max(0, len(items) - MAX_INSTANCES_WITH_EVIDENCE),
            )
        )
    return groups


def _natural(control_id: str) -> list[Any]:
    """Sort "1.8" before "1.10" and "PR.AA-01" before "PR.AA-05"."""
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", control_id)]


def _framework_appendix(groups: list[FindingGroup]) -> list[dict[str, Any]]:
    """Framework -> control -> the findings related to it (CIS, NIST CSF, SOC 2)."""
    frameworks: dict[str, dict[str, Any]] = {}
    for group in groups:
        for ref in group.framework_refs:
            key = ref["framework"]
            framework = frameworks.setdefault(
                key, {"name": f"{ref['framework_name']} {ref['version']}", "controls": {}}
            )
            control = framework["controls"].setdefault(
                ref["control_id"],
                {
                    "id": ref["control_id"],
                    "title": ref["title"],
                    "verified": ref["verified"],
                    "findings": [],
                },
            )
            control["findings"].append(f"{group.number} {group.title}")
    return [
        {
            "name": frameworks[key]["name"],
            "controls": [
                frameworks[key]["controls"][c]
                for c in sorted(frameworks[key]["controls"], key=_natural)
            ],
        }
        for key in sorted(frameworks)  # cis_*, nist_csf, soc2
    ]


def _checks_run(report: AssessmentReport) -> list[dict[str, Any]]:
    run = {r.rule_id for r in report.check_results}
    return [
        {
            "rule_id": rule.metadata.rule_id,
            "title": rule.metadata.title,
            "severity": rule.metadata.severity,
            "limitations": list(rule.metadata.limitations),
        }
        for rule in ALL_RULES
        if rule.metadata.rule_id in run
    ]


def _overall_rating(counts: dict[Severity, int]) -> Severity | None:
    return next((s for s in SEVERITY_ORDER if counts.get(s, 0) > 0), None)


def _date(value: datetime) -> str:
    return value.strftime("%d %B %Y, %H:%M UTC")


def build_context(report: AssessmentReport) -> dict[str, Any]:
    counts = {s: report.summary.by_severity.get(s, 0) for s in SEVERITY_ORDER}
    groups = _groups(report.findings)
    finalized = report.source.assessment_status == "finalized"
    return {
        "r": report,
        "counts": counts,
        "severities": SEVERITY_ORDER,
        "total": report.summary.total_findings,
        "rating": _overall_rating(counts),
        "groups": groups,
        "top_risks": [g for g in groups if g.severity in (Severity.CRITICAL, Severity.HIGH)],
        "frameworks": _framework_appendix(groups),
        "checks": _checks_run(report),
        "not_evaluated": report.not_evaluated,
        "draft": not finalized,
        "provider": "AWS" if report.provider.value == "aws" else "Microsoft Azure",
        "account_label": "account" if report.provider.value == "aws" else "subscription",
        "scan_date": _date(report.scan_completed_at),
        "generated": _date(report.generated_at),
        "regions": ", ".join(report.regions) or "all enabled regions",
        "max_bar": max(counts.values()) or 1,
    }


# ------------------------------------------------------------------ rendering


def render_html(report: AssessmentReport) -> str:
    return _environment.get_template("report.html.j2").render(**build_context(report))


def _no_fetch_fetcher() -> Any:
    """A WeasyPrint URL fetcher that allows only data: URIs (two layers: the
    built-in protocol allowlist, plus an explicit check that logs refusals)."""
    from weasyprint.urls import URLFetcher

    class NoNetworkFetcher(URLFetcher):
        def fetch(self, url: str, headers: dict | None = None) -> Any:
            if not url.lower().startswith("data:"):
                logger.warning(
                    "pdf renderer blocked a resource fetch",
                    extra={"scheme": url.split(":", 1)[0][:16]},
                )
                raise ValueError("external resources are not allowed in reports")
            return super().fetch(url, headers)

    return NoNetworkFetcher(allowed_protocols={"data"}, allow_redirects=False, timeout=1)


def to_pdf(report: AssessmentReport) -> bytes:
    """Render the report as PDF bytes."""
    # Imported here: WeasyPrint loads system libraries (Pango); importing it lazily
    # keeps every other part of the platform independent of them.
    from weasyprint import CSS, HTML

    css = CSS(
        string=(TEMPLATES / "report.css").read_text(encoding="utf-8"),
        url_fetcher=_no_fetch_fetcher(),
    )
    document = HTML(string=render_html(report), base_url=None, url_fetcher=_no_fetch_fetcher())
    return document.write_pdf(stylesheets=[css])
