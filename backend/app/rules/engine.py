"""The rule engine: runs every applicable rule against an inventory, safely.

Guarantees, each covered by tests:
1. Missing data is never a pass. If data a rule needs could not be collected:
   - account-scope rules are not run at all; they report ERROR ("not evaluated"),
     because concluding "nothing exists" from missing data would be wrong;
   - resource-scope rules judge the resources that WERE collected, plus one ERROR
     per gap, so real findings are still reported.
2. One broken rule never stops the scan: its exception becomes an ERROR result.
3. A rule with nothing to judge reports NOT_APPLICABLE, so every rule that ran
   leaves a visible outcome.
4. Every FAIL becomes exactly one Finding (one per rule per resource) with the
   rule's explanation, evidence and framework references.
"""

import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from app.domain.enums import CheckStatus
from app.domain.findings import (
    AssessmentResult,
    CheckResult,
    Finding,
    RuleRun,
    finding_fingerprint,
)
from app.domain.inventory import Inventory
from app.frameworks.catalog import FrameworkCatalog, load_catalog
from app.rules.base import Rule
from app.rules.registry import ALL_RULES

# Increase when engine semantics change (e.g. how gaps are handled), so stored
# results record which logic produced them.
ENGINE_VERSION = "1"

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RuleEngine:
    def __init__(
        self,
        rules: Sequence[Rule] = ALL_RULES,
        catalog: FrameworkCatalog | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        ids = [rule.metadata.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule IDs must be unique")
        self._rules = tuple(rules)
        self._catalog = catalog or load_catalog()
        self._clock = clock

    def run(self, inventory: Inventory) -> AssessmentResult:
        started_at = self._clock()
        applicable = [r for r in self._rules if inventory.provider in r.metadata.providers]

        results: list[CheckResult] = []
        findings: list[Finding] = []
        for rule in applicable:
            rule_results = self._evaluate(rule, inventory)
            results.extend(rule_results)
            findings.extend(
                self._to_finding(rule, result, started_at)
                for result in rule_results
                if result.status == CheckStatus.FAIL
            )

        findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.resource_id or ""))
        return AssessmentResult(
            provider=inventory.provider,
            account_id=inventory.account_id,
            engine_version=ENGINE_VERSION,
            started_at=started_at,
            completed_at=self._clock(),
            rules_run=tuple(
                RuleRun(rule_id=r.metadata.rule_id, rule_version=r.metadata.version)
                for r in applicable
            ),
            results=tuple(results),
            findings=tuple(findings),
        )

    def _evaluate(self, rule: Rule, inventory: Inventory) -> list[CheckResult]:
        meta = rule.metadata
        resource_types = meta.required_resource_types[inventory.provider]
        gaps = inventory.gaps_for(resource_types)

        def error(message: str, region: str | None = None) -> CheckResult:
            return CheckResult(
                rule_id=meta.rule_id,
                provider=inventory.provider,
                account_id=inventory.account_id,
                status=CheckStatus.ERROR,
                message=message,
                region=region,
            )

        gap_errors = [
            error(
                f"Not evaluated{f' in {g.region}' if g.region else ''}: "
                f"{g.resource_type} could not be collected ({g.reason}).",
                region=g.region,
            )
            for g in gaps
        ]
        if meta.scope == "account" and gap_errors:
            return gap_errors

        try:
            results = list(rule.evaluate(inventory))
        except Exception as exc:
            # Only the exception type is recorded: its message could contain
            # collected data. Details belong in a debugging session, not a report.
            logger.warning(
                "rule evaluation failed",
                extra={"rule_id": meta.rule_id, "error_type": type(exc).__name__},
            )
            return [error(f"Not evaluated: the rule failed internally ({type(exc).__name__}).")]

        # A buggy rule must not be able to attribute results to another rule or account.
        if any(r.rule_id != meta.rule_id or r.account_id != inventory.account_id for r in results):
            logger.warning("rule returned invalid results", extra={"rule_id": meta.rule_id})
            return [error("Not evaluated: the rule produced invalid results.")]

        if not results and not gap_errors:
            return [
                CheckResult(
                    rule_id=meta.rule_id,
                    provider=inventory.provider,
                    account_id=inventory.account_id,
                    status=CheckStatus.NOT_APPLICABLE,
                    message=f"No in-scope resources found ({', '.join(resource_types)}).",
                )
            ]
        return results + gap_errors

    def _to_finding(self, rule: Rule, result: CheckResult, detected_at: datetime) -> Finding:
        meta = rule.metadata
        return Finding(
            finding_id=finding_fingerprint(
                meta.rule_id, result.provider, result.account_id, result.resource_id
            ),
            rule_id=meta.rule_id,
            rule_version=meta.version,
            title=meta.title,
            provider=result.provider,
            account_id=result.account_id,
            category=meta.category,
            severity=meta.severity,
            resource_id=result.resource_id,
            resource_name=result.resource_name,
            resource_type=result.resource_type,
            region=result.region,
            message=result.message,
            description=meta.description,
            risk=meta.risk,
            recommendation=meta.recommendation,
            evidence=result.evidence,
            framework_refs=self._catalog.refs_for(meta.rule_id, result.provider),
            detected_at=detected_at,
        )
