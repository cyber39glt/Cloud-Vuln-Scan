# Writing a Security Rule

This guide explains how the rule engine works and how to add a rule. Read
[ADR 0006](decisions/0006-normalized-model-and-rule-engine.md) and
[ADR 0013](decisions/0013-finding-granularity-and-collection-gaps.md) for the reasoning.

## How the pieces fit

```
Inventory (normalized resources + collection gaps)
     │
     ▼
RuleEngine.run()
  ├─ picks rules that support the inventory's provider
  ├─ for each rule: checks gaps → calls rule.evaluate() safely → CheckResults
  └─ turns every FAIL into a Finding (+ framework references from mappings.toml)
     │
     ▼
AssessmentResult (results + findings + summary): the single dataset for all outputs
```

| File | Role |
|---|---|
| `app/domain/inventory.py` | `Resource`, `NetworkIngressRule` facet, `CollectionGap`, `Inventory` |
| `app/domain/findings.py` | `Evidence`, `CheckResult`, `Finding`, `FrameworkRef`, `AssessmentResult` |
| `app/rules/base.py` | `RuleMetadata` and the `Rule` base class |
| `app/rules/engine.py` | `RuleEngine` |
| `app/rules/registry.py` | The list of enabled rules |
| `app/frameworks/mappings.toml` | Rule → CIS / NIST CSF 2.0 / SOC 2 references |

## Enabled rules

| ID | Provider | Severity | Scope | Checks |
|---|---|---|---|---|
| `NET-001` | AWS, Azure | High | resource | SSH (22) open to the internet |
| `NET-002` | AWS, Azure | High | resource | RDP (3389) open to the internet |
| `AWS-IAM-001` | AWS | Critical | account | Root user without MFA |
| `AWS-IAM-002` | AWS | Critical | account | Root user has access keys |
| `AWS-IAM-003` | AWS | High | resource | IAM user with console password but no MFA |
| `AWS-IAM-004` | AWS | Medium | resource | Active access keys unused for 45+ days |
| `AWS-IAM-005` | AWS | Medium | account | No password policy, or minimum length below 14 |
| `AWS-IAM-006` | AWS | Medium | account | AdministratorAccess attached to users or groups |
| `AWS-STO-001` | AWS | Medium | account | Account-level S3 Block Public Access not fully on |
| `AWS-STO-002` | AWS | High | resource | S3 bucket public via policy or ACL, not neutralized by Block Public Access |
| `AWS-EXP-001` | AWS | High | resource | RDS instance publicly accessible |
| `AWS-LOG-001` | AWS | High | account | No multi-region CloudTrail trail logging |
| `AZ-STO-001` | Azure | Medium | resource | Storage account allows anonymous blob access |
| `AZ-STO-002` | Azure | Medium | resource | Storage account accepts HTTP (secure transfer off) |
| `AZ-STO-003` | Azure | Medium | resource | Storage account minimum TLS below 1.2 |
| `AZ-EXP-001` | Azure | High | resource | SQL server firewall allows 0.0.0.0–255.255.255.255 |
| `AZ-EXP-002` | Azure | Medium | resource | SQL server allows all Azure services (0.0.0.0–0.0.0.0) |
| `AZ-LOG-001` | Azure | Medium | account | Activity Log (Administrative + Security) not exported |
| `AZ-SEC-001` | Azure | Medium | account | Defender plans for servers, SQL, storage or Key Vault not on Standard |

Each rule's description, risk, recommendation and limitations are in its source file and
appear in reports. Framework references are in `app/frameworks/mappings.toml`.

## The four outcomes

| Status | Meaning | Becomes a finding? |
|---|---|---|
| `pass` | Evaluated, no weakness | No |
| `fail` | Evaluated, weakness found (must include evidence) | **Yes**, one per resource |
| `error` | **Not evaluated**: data missing or the rule crashed | No, but shown as "not evaluated" |
| `not_applicable` | Nothing in scope (e.g. no storage accounts) | No |

## Steps to add a rule

1. **Choose an ID**: `NET-003` for a cross-cloud rule, `AWS-IAM-001` / `AZ-NET-001` for
   provider-specific rules. Never reuse or renumber an ID.
2. **Pick the scope**:
   - `resource`: judge each resource separately (most rules).
   - `account`: judge the account as a whole, typically "does at least one X exist?".
     The engine will not run account rules when their data has gaps.
3. **Create the file** in `app/rules/common/`, `app/rules/aws/` or `app/rules/azure/`:

```python
class MyRule(Rule):
    metadata = RuleMetadata(
        rule_id="AZ-NET-001",
        title="Short, specific title",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        scope="resource",
        description="What is wrong, in one or two sentences.",
        risk="Why it matters to the client, without jargon.",
        recommendation="What to do about it, concretely.",
        required_resource_types={Provider.AZURE: ("azure.network.public_ip",)},
        required_permissions={Provider.AZURE: ("Microsoft.Network/publicIPAddresses/read",)},
        limitations=("Anything the rule cannot see or decide.",),
    )

    def evaluate(self, inventory):
        for resource in self.resources(inventory):
            if <good>:
                yield self.passed(resource, "Plain-language reason.")
            else:
                yield self.failed(resource, "Plain-language reason.", [Evidence(...)])
```

4. **Register it** in `app/rules/registry.py`.
5. **Map it** in `app/frameworks/mappings.toml`: CIS (for each provider), NIST CSF 2.0
   and SOC 2. Use `verified = false` unless you checked the official document.
   For CIS and SOC 2, write your own short title; never copy their text.
6. **Test it** in `tests/test_rules.py`: at least one FAIL case, one PASS case and the
   edge cases (port ranges, unset values, etc.).
7. Run `.\scripts\dev.ps1 check`.

## Rules for rules

- **No input/output.** A rule reads only the inventory it is given. Importing cloud
  SDKs, HTTP clients, sockets, subprocesses or the database fails the test suite.
- **Evidence is mandatory for a FAIL** and should contain only the fields that prove
  the point. Evidence is redacted automatically, but do not rely on that.
- **Unknown is not good.** If a value is missing and the provider documents a risky
  default, treat it as risky and say so (see `AZ-STO-001`).
- **Share logic, not rules.** Similar rules (e.g. `NET-001` SSH and `NET-002` RDP) share
  a helper module whose name starts with `_`, but each stays a separate rule with its
  own ID and framework mappings, so findings map precisely.
- **Say what you cannot see** in `limitations`; it appears in reports.
- **Change logic → bump `version`** in the metadata.
