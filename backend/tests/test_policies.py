"""Generated least-privilege permissions (ADR 0025)."""

import json
import re
import shlex

from app import policies
from app.providers.aws import guard as aws_guard
from app.providers.azure import guard as azure_guard


def test_generated_files_are_up_to_date():
    """Fails when checks gain or lose permissions and `python -m app.policies` was
    not run: clients would otherwise be asked for the wrong permissions."""
    assert policies.outdated() == []


def test_aws_policy_is_exactly_the_guard_allowlist():
    actions = set(policies.aws_actions())
    assert actions == aws_guard.assessment_permissions() | {"ec2:DescribeRegions"}
    # Every action the policy grants is something the guard lets the SDK call.
    operations = aws_guard.assessment_operations()
    assert {aws_guard.OPERATION_FOR_PERMISSION.get(a, a) for a in actions} <= operations


def test_aws_policy_contains_only_reads():
    for action in policies.aws_actions():
        service, name = action.split(":", 1)
        assert re.fullmatch(r"[a-z0-9-]+", service)
        assert "*" not in action
        assert name.startswith(("Describe", "List", "Get")) or action in (
            aws_guard.READ_ONLY_EXCEPTIONS
        ), action


def test_template_contains_the_generated_actions():
    template = policies.AWS_TEMPLATE.read_text(encoding="utf-8")
    block = template.split(policies.BEGIN, 1)[1].split(policies.END, 1)[0]
    listed = [line.strip().removeprefix("- ") for line in block.strip().splitlines()]
    assert listed == policies.aws_actions()
    # The managed policies are only an option, not the default.
    assert "Default: LeastPrivilege" in template
    assert "UseAwsManaged" in template


def test_azure_role_is_read_only_and_scoped():
    role = policies.azure_role("Acme Consulting", "11111111-2222-3333-4444-555555555555")
    assert role["Actions"] == sorted(azure_guard.assessment_permissions(), key=str.lower)
    assert all(a.endswith("/read") and "*" not in a for a in role["Actions"])
    assert role["DataActions"] == [] and role["NotDataActions"] == []
    assert role["AssignableScopes"] == ["/subscriptions/11111111-2222-3333-4444-555555555555"]
    assert role["Name"] == "Acme Consulting Security Assessment (read-only)"


def test_azure_commands_are_safely_quoted():
    commands = policies.azure_role_commands("O'Brien & Co", "sub-id", "app-id")
    create = shlex.split(commands[0])
    assert create[:4] == ["az", "role", "definition", "create"]
    assert json.loads(create[-1])["Name"] == "O'Brien & Co Security Assessment (read-only)"
    assign = shlex.split(commands[1])
    assert assign[assign.index("--role") + 1] == "O'Brien & Co Security Assessment (read-only)"
