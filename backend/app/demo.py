"""Run the rule engine on the sample inventories and print the outcome.

    python -m app.demo          human-readable summary
    python -m app.demo --json   the full AssessmentResult datasets as JSON

No cloud access: the input is app/sample_data.py.
"""

import argparse
import json

from app.domain.findings import AssessmentResult
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory, sample_azure_inventory


def _print_summary(result: AssessmentResult) -> None:
    print(f"\n=== {result.provider.value.upper()} {result.account_id} ===")
    statuses = ", ".join(f"{s.value}={n}" for s, n in result.status_counts().items())
    print(f"Check results: {statuses}")
    severities = ", ".join(f"{s.value}={n}" for s, n in result.severity_counts().items() if n)
    print(f"Findings: {len(result.findings)} ({severities or 'none'})")

    for finding in result.findings:
        target = finding.resource_name or "(account)"
        print(f"\n  [{finding.severity.value.upper()}] {finding.rule_id} {finding.title}")
        print(f"    Resource : {target} ({finding.region or 'account-wide'})")
        print(f"    Detail   : {finding.message}")
        print(f"    Evidence : {finding.evidence[0].summary}")
        refs = ", ".join(
            f"{r.framework.value} {r.control_id}{'' if r.verified else '*'}"
            for r in finding.framework_refs
        )
        print(f"    Mapped to: {refs}")

    for check in result.results:
        if check.status.value in ("error", "not_applicable"):
            print(f"\n  ({check.status.value}) {check.rule_id}: {check.message}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print full JSON datasets")
    args = parser.parse_args(argv)

    engine = RuleEngine()
    results = [engine.run(sample_aws_inventory()), engine.run(sample_azure_inventory())]

    if args.json:
        print(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
        return
    for result in results:
        _print_summary(result)
    print("\n* = framework reference not yet verified against the official document")


if __name__ == "__main__":
    main()
