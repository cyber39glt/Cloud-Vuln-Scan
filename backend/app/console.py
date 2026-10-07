"""Plain-text rendering of an AssessmentResult for terminals (demo and CLI scans).

A temporary view until the dashboard exists; it reads the same dataset that the
dashboard and reports will use.
"""

from app.domain.enums import CheckStatus
from app.domain.findings import AssessmentResult

UNVERIFIED_NOTE = "* = framework reference not yet verified against the official document"


def format_summary(result: AssessmentResult) -> str:
    lines = [f"\n=== {result.provider.value.upper()} {result.account_id} ==="]
    statuses = ", ".join(f"{s.value}={n}" for s, n in result.status_counts().items())
    lines.append(f"Check results: {statuses}")
    severities = ", ".join(f"{s.value}={n}" for s, n in result.severity_counts().items() if n)
    lines.append(f"Findings: {len(result.findings)} ({severities or 'none'})")

    for finding in result.findings:
        target = finding.resource_name or "(account)"
        refs = ", ".join(
            f"{r.framework.value} {r.control_id}{'' if r.verified else '*'}"
            for r in finding.framework_refs
        )
        lines += [
            f"\n  [{finding.severity.value.upper()}] {finding.rule_id} {finding.title}",
            f"    Resource : {target} ({finding.region or 'account-wide'})",
            f"    Detail   : {finding.message}",
            f"    Evidence : {finding.evidence[0].summary}",
            f"    Mapped to: {refs}",
        ]

    for check in result.results:
        if check.status in (CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE):
            lines.append(f"\n  ({check.status.value}) {check.rule_id}: {check.message}")
    return "\n".join(lines)
