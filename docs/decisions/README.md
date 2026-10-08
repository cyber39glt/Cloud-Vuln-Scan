# Architecture Decision Records

An ADR records one significant decision: the context, what was decided, and the
consequences. They are never deleted; a changed decision gets a new ADR that
supersedes the old one, so the history of *why* is preserved.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-read-only-security-boundary.md) | Strict read-only boundary, enforced in two layers | Accepted |
| [0003](0003-modular-monolith-api-and-worker.md) | Modular monolith: API + worker, PostgreSQL job queue | Accepted |
| [0004](0004-technology-stack.md) | Technology stack | Accepted |
| [0005](0005-cloud-access-model.md) | Cloud access: AWS AssumeRole + ExternalId, Azure multi-tenant app | Accepted |
| [0006](0006-normalized-model-and-rule-engine.md) | Normalized resource model and rule engine | Accepted |
| [0007](0007-single-dataset-and-finding-review.md) | One assessment dataset; review layer; finalization | Accepted |
| [0008](0008-framework-mapping.md) | Framework mapping: CIS, NIST CSF 2.0, SOC 2 | Accepted |
| [0009](0009-authentication-and-authorization.md) | Local auth, mandatory TOTP MFA, roles, assigned-client isolation | Accepted |
| [0010](0010-hosting-agnostic-containers.md) | Hosting-agnostic containers, environment-based configuration | Accepted |
| [0011](0011-windows-first-docker-development.md) | Windows-first, Docker-based developer experience | Accepted |
| [0012](0012-private-now-open-source-later.md) | Private repository now, open source later | Accepted |
| [0013](0013-finding-granularity-and-collection-gaps.md) | Finding granularity, collection gaps, rule purity | Accepted |
| [0014](0014-aws-connector-and-dev-identity.md) | AWS connector: guard design, client role, dev identity | Accepted |
| [0015](0015-persistence-and-client-isolation.md) | Persistence, database-enforced client isolation, immutable results | Accepted |
| [0016](0016-report-dataset-and-exports.md) | Report dataset; JSON/CSV exports; CSV-injection protection | Accepted |
| [0017](0017-azure-connector.md) | Azure connector: pipeline guard, client access, dev identity | Accepted |
| [0018](0018-rule-expansion-r1.md) | Rule expansion R1: credential report exception, no guessing, ARM lists | Accepted |
| [0019](0019-api-worker-and-pre-auth-boundary.md) | Data API, scan worker, and the boundary before user authentication | Accepted (partly superseded by 0020) |
| [0020](0020-authentication-implementation.md) | Authentication and authorization: implementation details | Accepted |
| [0021](0021-dashboard.md) | Dashboard: same-origin React app with a strict Content-Security-Policy | Accepted |
| [0022](0022-pdf-reports.md) | PDF reports: WeasyPrint with escaped templates and no resource fetching | Accepted |

To add one, copy the structure of an existing ADR and use the next number.
