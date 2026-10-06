"""The engine's guarantees: missing data is never a pass, a broken rule never stops
the scan, every rule leaves an outcome, every FAIL becomes one finding."""

from collections.abc import Iterator

from app.domain.enums import Category, CheckStatus, Framework, Provider, Severity
from app.domain.findings import CheckResult
from app.domain.inventory import CollectionGap, Inventory
from app.rules.base import Rule, RuleMetadata
from app.rules.engine import RuleEngine
from tests.factories import NOW, ingress, inventory, nsg, security_group, storage_account


def by_rule(result, rule_id):
    return [r for r in result.results if r.rule_id == rule_id]


def test_failures_become_findings_with_explanation_and_frameworks():
    result = RuleEngine(clock=lambda: NOW).run(
        inventory(Provider.AWS, security_group("open", ingress(port=22)))
    )

    [finding] = [f for f in result.findings if f.rule_id == "NET-001"]
    assert finding.severity == Severity.HIGH
    assert finding.category == Category.NETWORK
    assert finding.resource_name == "open"
    assert finding.risk and finding.recommendation and finding.description
    assert finding.evidence
    assert finding.detected_at == NOW
    frameworks = {ref.framework for ref in finding.framework_refs}
    # CIS AWS for an AWS finding, never CIS Azure.
    assert frameworks == {Framework.CIS_AWS, Framework.NIST_CSF, Framework.SOC2}


def test_azure_findings_get_azure_cis_references():
    result = RuleEngine().run(inventory(Provider.AZURE, nsg("n", ingress(port=3389))))
    [finding] = result.findings
    assert finding.rule_id == "NET-002"
    cis = [ref.control_id for ref in finding.framework_refs if ref.framework == Framework.CIS_AZURE]
    assert cis == ["6.1"]  # the RDP control only, not the SSH one
    assert Framework.CIS_AZURE in {ref.framework for ref in finding.framework_refs}
    assert Framework.CIS_AWS not in {ref.framework for ref in finding.framework_refs}


def test_only_rules_for_the_inventory_provider_run():
    result = RuleEngine().run(inventory(Provider.AZURE, storage_account("s", False)))
    assert {r.rule_id for r in result.rules_run} == {"NET-001", "NET-002", "AZ-STO-001"}


def test_account_rule_with_collection_gap_is_not_evaluated_not_failed():
    """No trail data because of AccessDenied must NOT be reported as 'no CloudTrail'."""
    gap = CollectionGap(resource_type="aws.cloudtrail.trail", reason="AccessDenied")
    result = RuleEngine().run(inventory(Provider.AWS, gaps=(gap,)))

    [check] = by_rule(result, "AWS-LOG-001")
    assert check.status == CheckStatus.ERROR
    assert "AccessDenied" in check.message
    assert not [f for f in result.findings if f.rule_id == "AWS-LOG-001"]


def test_resource_rule_with_gap_reports_findings_and_the_gap():
    gap = CollectionGap(
        resource_type="aws.ec2.security_group", region="us-east-1", reason="AccessDenied"
    )
    result = RuleEngine().run(
        inventory(Provider.AWS, security_group("open", ingress(port=22)), gaps=(gap,))
    )

    checks = by_rule(result, "NET-001")
    assert [c.status for c in checks] == [CheckStatus.FAIL, CheckStatus.ERROR]
    assert checks[1].region == "us-east-1"
    assert [f.resource_name for f in result.findings if f.rule_id == "NET-001"] == ["open"]


def test_rule_with_nothing_to_judge_is_not_applicable():
    result = RuleEngine().run(inventory(Provider.AZURE))
    assert {r.status for r in result.results} == {CheckStatus.NOT_APPLICABLE}
    assert result.findings == ()


class _CrashingRule(Rule):
    metadata = RuleMetadata(
        rule_id="TST-001",
        title="Crashes",
        category=Category.NETWORK,
        severity=Severity.LOW,
        scope="resource",
        description="d",
        risk="r",
        recommendation="r",
        required_resource_types={Provider.AWS: ("aws.ec2.security_group",)},
        required_permissions={Provider.AWS: ("ec2:DescribeSecurityGroups",)},
    )

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        raise RuntimeError("boom with password=hunter2")


class _WrongAccountRule(_CrashingRule):
    metadata = _CrashingRule.metadata.model_copy(update={"rule_id": "TST-002"})

    def evaluate(self, inventory: Inventory) -> Iterator[CheckResult]:
        yield CheckResult(
            rule_id="TST-002",
            provider=Provider.AWS,
            account_id="999999999999",
            status=CheckStatus.PASS,
            message="claims another account",
        )


def test_crashing_rule_becomes_error_and_scan_continues():
    from app.rules.registry import ALL_RULES

    engine = RuleEngine(rules=(_CrashingRule(), *ALL_RULES))
    result = engine.run(inventory(Provider.AWS, security_group("open", ingress(port=22))))

    [crash] = by_rule(result, "TST-001")
    assert crash.status == CheckStatus.ERROR
    assert "RuntimeError" in crash.message
    assert "hunter2" not in crash.message  # exception text is never stored
    assert by_rule(result, "NET-001")[0].status == CheckStatus.FAIL  # others still ran


def test_rule_cannot_report_for_another_account():
    result = RuleEngine(rules=(_WrongAccountRule(),)).run(
        inventory(Provider.AWS, security_group("sg"))
    )
    [check] = result.results
    assert check.status == CheckStatus.ERROR
    assert check.account_id != "999999999999"


def test_findings_sorted_by_severity_and_ids_stable_between_runs():
    inv = inventory(
        Provider.AZURE,
        storage_account("public", True),
        nsg("open", ingress(port=22)),
    )
    first, second = RuleEngine().run(inv), RuleEngine().run(inv)

    assert [f.severity for f in first.findings] == [Severity.HIGH, Severity.MEDIUM]
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]


def test_summary_counts():
    result = RuleEngine().run(
        inventory(Provider.AZURE, storage_account("public", True), storage_account("ok", False))
    )
    assert result.severity_counts()[Severity.MEDIUM] == 1
    counts = result.status_counts()
    assert counts[CheckStatus.FAIL] == 1
    assert counts[CheckStatus.PASS] == 1
    assert counts[CheckStatus.NOT_APPLICABLE] == 2  # no NSGs: NET-001 and NET-002


def test_result_is_json_serializable():
    result = RuleEngine().run(inventory(Provider.AWS, security_group("open", ingress(port=22))))
    data = result.model_dump(mode="json")
    assert data["findings"][0]["severity"] == "high"
    assert data["engine_version"] == "1"
