# 0027. Apache-2.0 licence and public release preparation

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

ADR 0012 kept the repository private during development and deferred the licence to
M15. The owner chose the licence (Apache-2.0) from Apache-2.0, AGPL-3.0 and MIT.

## Decision

- **Licence: Apache License 2.0** (official text in `LICENSE`). Permissive, with an
  explicit patent grant; common for security tooling. `NOTICE` names the copyright
  holder and the main third-party components and their licences.
- **Dependency licences checked:** Python and dashboard dependencies are permissive
  (MIT, BSD, Apache, ISC) or weak copyleft used unmodified as separate libraries
  (psycopg: LGPL-3.0; certifi: MPL-2.0; pyphen: LGPL/MPL option). The bundled Inter
  font is under the SIL OFL 1.1; its licence ships with the dashboard
  (`/licenses/Inter-OFL-1.1.txt`).
- **Pre-release audit:** full-history secret scan clean; no personal data in files
  or commits; no internal paths; only fictitious account identifiers in tests.
- **Community files:** CONTRIBUTING (read-only rule first), Contributor Covenant 2.1
  code of conduct, issue forms that warn against posting client data, a pull request
  checklist, private vulnerability reporting in SECURITY.md, CHANGELOG.
- **Supply chain:** the CI checkout action is pinned to a commit SHA (v6.1.0);
  Dependabot updates GitHub Actions (keeping SHAs current), Python (uv), npm and
  Docker images weekly. Docker base images stay on version tags so that rebuilds pick
  up security patches; Dependabot proposes newer tags.
- **The owner performs the release** ([release-checklist.md](../release-checklist.md)):
  merging into `main`, repository security settings, changing visibility, and
  publishing v0.1.0 are owner actions in GitHub.

## Consequences

- Anyone may use, modify and redistribute CloudSecura, including commercially, under
  the Apache-2.0 terms; contributions are accepted under the same licence.
- The threat model's "CI actions pinned by tag" risk is resolved for actions; images
  remain tag-based by decision.
