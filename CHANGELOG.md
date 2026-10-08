# Changelog

All notable changes. Versions follow [Semantic Versioning](https://semver.org/);
0.x releases may change behaviour between minor versions.

## [0.1.0] - unreleased (first public release)

The first release, built in milestones M0 to M15 (details in
[docs/architecture.md](docs/architecture.md#roadmap) and the
[decision records](docs/decisions/)).

### Assessments
- Read-only connectors for AWS (AssumeRole with ExternalId) and Azure (multi-tenant
  app), each with an application-side guard that blocks every non-read call.
- 19 checks: SSH/RDP exposure (AWS, Azure); AWS root MFA and keys, console users
  without MFA, stale access keys, password policy, AdministratorAccess, S3 public
  access, public RDS, CloudTrail; Azure storage anonymous access, HTTPS and TLS, SQL
  firewall, Activity Log export, Defender plans.
- Evidence for every finding; mapping to CIS Benchmarks, NIST CSF 2.0 and SOC 2.
- Least-privilege client permissions generated from the code (AWS CloudFormation
  template, Azure custom role).

### Platform
- Web dashboard (React): dashboard charts, clients, assessments with live scan
  progress, reports with filters, dark and light themes, public showcase page.
- Finding review (confirm, false positive, accepted risk, severity change with a
  reason) and finalization of a signed, frozen report.
- Reports as PDF, CSV and JSON (published JSON Schema), all from one dataset.
- Accounts: mandatory authenticator-app MFA, recovery codes, first-run setup page,
  invitation links, Admin and Consultant roles with per-client access, append-only
  audit log.

### Security and operations
- Threat model and code-level security review (M13); every fix has a regression test.
- Tamper evidence on stored results (SHA-256 and keyed HMAC, database triggers).
- Production stack: Caddy with automatic HTTPS, internal networks, restricted database
  login, hardened containers, nightly backups, tested restore.
- CI: lint, tests, migration check, production stack smoke test, dependency audit,
  full-history secret scan; Dependabot.

### Known limitations
- AWS and Azure connectors tested against simulated APIs only so far.
- Keyless platform cloud sign-in depends on the hosting choice.
- See [docs/threat-model.md](docs/threat-model.md#residual-risks-accepted-or-deferred).
