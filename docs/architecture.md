# Architecture Overview

This document describes the **target architecture** of the platform and what exists
today. Individual decisions and their reasoning are recorded as
[Architecture Decision Records](decisions/).

## Purpose

Consultants assess a client's AWS account or Azure subscription for security
weaknesses. The platform automates the repetitive part, evidence gathering and
checking, so an engagement takes roughly 10-12 hours instead of 25-30, with
consistent and defensible results.

User experience: **Connect → Scan → Review → Report.**

## Security boundary

The platform is **strictly read-only** against client environments
([ADR 0002](decisions/0002-read-only-security-boundary.md)). Enforcement is layered:
client-granted read-only roles plus an application-side allowlist of read
operations. No remediation, modification, deletion, deployment or exploitation.

## System context

```
 Consultant (browser)
        │ HTTPS
        ▼
 ┌──────────────────────────── Platform (containers) ───────────────────────────┐
 │  Dashboard (React SPA) ──► API (FastAPI) ──► PostgreSQL ◄── Worker process   │
 │                                 │ enqueue scan job            │              │
 │                                 └─────────────────────────────┘              │
 └──────────────────────────────────────────────────────────────┬───────────────┘
                                                                │ temporary, read-only
                                                                ▼ credentials
                                                   Client AWS / Azure APIs
```

- **API process:** authentication, clients, assessments, finding review, exports.
- **Worker process:** runs scans (minutes long, hundreds of API calls) outside web
  requests. Jobs are queued in a PostgreSQL table; no extra queue infrastructure
  ([ADR 0003](decisions/0003-modular-monolith-api-and-worker.md)).
- **PostgreSQL:** the single store for all state.

## Internal modules (modular monolith)

| Module | Responsibility | Status |
|---|---|---|
| `core` | Configuration, logging, database engine | **M0 ✓** |
| `api` | HTTP routes ([guide](api.md)) | Health **M0 ✓**; data API **M8 ✓**; login + roles **M9 ✓** |
| `auth`, `audit` | Users, sessions, MFA, roles, client assignments, audit log ([guide](users.md)) | **M9 ✓** |
| `providers/aws`, `providers/azure` | Authentication, connection validation, read-only guard, collectors. **The only code that calls cloud SDKs.** | AWS **M2–M3 ✓** ([guide](aws-connection.md)); Azure **M6–M7 ✓** ([guide](azure-connection.md)) |
| `domain` | Normalized inventory (envelope + facets), check results, evidence, findings | **M1 ✓** (review layer: M12) |
| `rules` | Rule definitions and engine. **Never calls cloud APIs.** See [rules.md](rules.md) | **M1 ✓**; 19 rules after **R1 ✓** ([list](rules.md#enabled-rules)) |
| `frameworks` | CIS / NIST CSF 2.0 / SOC 2 mapping data | **M1 ✓** |
| `storage` | Database models, migrations, client-scoped repository ([data model](data-model.md)) | **M4 ✓** |
| `scanning` | One safe sequence: connect → verify account → collect → evaluate | **M3 ✓**; background worker + job queue **M8 ✓** |
| `reporting` | One dataset → JSON, CSV, PDF ([exports](exports.md)) | JSON/CSV **M5 ✓**; PDF M11 |

## Assessment data flow

```
Cloud APIs ─► Collectors ─► Normalized inventory ─► Rule engine
                                                       │
                       CheckResults (PASS / FAIL / ERROR / NOT_APPLICABLE)
                                                       │
                     Findings + Evidence + Severity + Framework references
                                                       │
                 Consultant review (status, notes, severity override + justification)
                                                       │
                         Finalized, hashed assessment dataset
                ┌──────────────┬──────────────┬──────────────┐
             Dashboard        PDF            CSV            JSON
```

A check that **could not run** is recorded as `ERROR` and reported as "not
evaluated", never as a pass
([ADR 0006](decisions/0006-normalized-model-and-rule-engine.md),
[ADR 0007](decisions/0007-single-dataset-and-finding-review.md)).

## Environments

The same container image runs everywhere; only environment variables differ
([ADR 0010](decisions/0010-hosting-agnostic-containers.md)).

| | Development | CI | Production |
|---|---|---|---|
| How it runs | `docker compose` via `scripts/dev.ps1` | `docker compose` in GitHub Actions | Host to be chosen (M14) |
| Image target | `dev` (tools + auto-reload) | `dev` + `prod` build | `prod` |
| Config source | `.env` | `.env.example` copy | Platform secret manager |

## What exists today

### M9: users, MFA, roles and audit

- Local accounts with Argon2id passwords; mandatory authenticator-app MFA with
  recovery codes; server-side sessions (idle and absolute timeouts); lockout and rate
  limiting; Admin / Consultant roles with assigned-client access enforced on every
  endpoint ([guide](users.md), [ADR 0020](decisions/0020-authentication-implementation.md)).
- Append-only audit log of logins, MFA, account changes, data access, scans and exports.
- `users` command-line tools to create the first admin and recover access.

### M8: API and background worker

- Data API under `/api/v1/clients/{client_id}/...`: clients, connections, assessments,
  scan requests, scan progress, report (JSON) and CSV ([guide](api.md)).
- Worker process (`python -m app.worker`, a Compose service) runs queued scans with
  the same sequence as the CLI; progress stages, heartbeat, interrupted-job recovery,
  graceful stop.
- Works in development/test only until M9 adds users; host allowlist, JSON-only
  changes and security headers protect the local API from browser-based attacks
  ([ADR 0019](decisions/0019-api-worker-and-pre-auth-boundary.md)).

### M7: Azure scanning

- Collectors for NSGs (inbound custom rules normalized to the shared facet) and storage
  accounts; optional region scope; gaps for denied reads
- `scanning.scan_azure`: confirm tenant and state → collect → evaluate; the same rules
  (`NET-001`, `NET-002`, `AZ-STO-001`) now run on real Azure data
- `dev.ps1 azure scan` (saved with `--client`), exports work unchanged
- Sandbox ARM fixture template, checked against the rules by a test

### M6: Azure connector

- Multi-tenant Entra app model: admin consent + Reader/Security Reader; no client secrets stored
- Read-only guard as an azure-core pipeline policy: GET only, ARM host only, allowlisted
  resource types; POST actions such as `listKeys` and data-plane hosts always refused
- Validation: identity, sign-in to client tenant, subscription tenant/state (fails
  closed), permission probes, guard self-test; `dev.ps1 azure connect|validate`
- Migration 0002: `tenant_id` on connections, required for Azure by the database

### M5: JSON and CSV exports

- `AssessmentReport`: one dataset built from a stored, hash-verified scan (summary,
  findings, not-evaluated items, notes, traceability to scan ID + SHA-256)
- JSON export with versioned schema and published JSON Schema
- CSV export (one row per finding) with CSV-injection protection
- `dev.ps1 assessments export`, `demo -save` to try exports without AWS

### M4: persistence

- PostgreSQL schema via Alembic: clients, connections, assessments, scan runs, findings
- Client isolation enforced by composite foreign keys and client-scoped repository
- Frozen scan snapshots with SHA-256 verification; database trigger blocks edits
- CLI: `clients`, `aws connect`, saved `aws scan --client`, `assessments list/show`

### M3: AWS scanning

- Collectors for security groups (all enabled regions, or a chosen scope) and CloudTrail
  trails with logging status, normalized into the inventory
- Failures recorded as collection gaps ("not evaluated"), never as passes
- `scanning.scan_aws`: confirm account → collect → evaluate; `dev.ps1 aws scan`
- Sandbox fixture template with deliberately weak security groups

### M2: AWS connector

- Read-only guard: allowlist of AWS operations enforced before any request is built
- AssumeRole with ExternalId into the client role; temporary credentials in memory only
- Connection validation (identity, role, account match, permissions, guard self-test)
- Client CloudFormation template with an explicit Deny on reading data and secrets
- `dev.ps1 aws external-id` / `dev.ps1 aws validate`

### M1: domain model and rule engine

- Provider-neutral models for inventory, check results, evidence and findings
- Rule engine with honest handling of missing data (`ERROR` = not evaluated)
- Four rules: `NET-001` / `NET-002` (SSH / RDP open to the internet, AWS + Azure),
  `AWS-LOG-001` (no multi-region CloudTrail), `AZ-STO-001` (anonymous blob access)
- Framework mappings in `app/frameworks/mappings.toml`
- `python -m app.demo` / `dev.ps1 demo`: runs the engine on sample data

### M0: foundation

- FastAPI application with `/health` (liveness) and `/health/ready` (database check)
- Environment-based configuration with production safety checks
- Structured JSON logging with secret redaction
- Docker Compose development environment (PostgreSQL + API)
- Windows development script, Ruff, pytest, Gitleaks, GitHub Actions CI

## Roadmap

| # | Milestone |
|---|---|
| **M0** | **Project foundation** ✓ |
| **M1** | **Domain model + rule engine on fixture data (no cloud)** ✓ |
| **M2** | **AWS connector: AssumeRole + ExternalId, validation, read-only guard** ✓ |
| **M3** | **AWS collectors + scan; sandbox test fixtures** ✓ |
| **M4** | **Persistence: schema, migrations, stored scan runs** ✓ |
| **M5** | **JSON + CSV exports** ✓ |
| **M6** | **Azure connector: multi-tenant app, validation, read-only guard** ✓ |
| **M7** | **Azure collectors + scan (ARM)** ✓ — Entra ID (Graph) checks come with new rules |
| **R1** | **Rule expansion: IAM, S3, RDS, Azure storage transport, SQL, Activity Log, Defender** ✓ ([ADR 0018](decisions/0018-rule-expansion-r1.md)) |
| **M8** | **API + background worker + scan progress** ✓ ([ADR 0019](decisions/0019-api-worker-and-pre-auth-boundary.md)) |
| **M9** | **Authentication (Argon2id, TOTP MFA), roles, client assignment, audit log** ✓ ([ADR 0020](decisions/0020-authentication-implementation.md)) |
| M10 | Dashboard |
| M11 | PDF report |
| M12 | Finding review workflow and assessment finalization |
| M13 | Hardening: threat model, generated least-privilege policies, security review |
| M14 | Hosting evaluation and deployment |
| M15 | Documentation, license decision, public release |
