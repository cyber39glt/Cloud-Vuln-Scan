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
| `api` | HTTP routes | Health only (**M0 ✓**) |
| `auth`, `audit` | Users, sessions, MFA, roles, client assignments, audit log | Planned |
| `providers/aws`, `providers/azure` | Authentication, connection validation, read-only guard, collectors. **The only code that calls cloud SDKs.** | AWS connection **M2 ✓** ([guide](aws-connection.md)); collectors M3; Azure M6 |
| `domain` | Normalized inventory (envelope + facets), check results, evidence, findings | **M1 ✓** (review layer: M12) |
| `rules` | Rule definitions and engine. **Never calls cloud APIs.** See [rules.md](rules.md) | **M1 ✓** (4 rules) |
| `frameworks` | CIS / NIST CSF 2.0 / SOC 2 mapping data | **M1 ✓** |
| `reporting` | One dataset → JSON, CSV, PDF | Planned |

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
| M3 | AWS collectors + AWS rules; misconfigured test environment in our own sandbox |
| M4 | Persistence: schema, migrations, stored scan runs |
| M5 | JSON + CSV exports |
| M6 | Azure connector: multi-tenant app, validation, read-only guard |
| M7 | Azure collectors + rules (ARM + minimal Graph) |
| M8 | API + background worker + scan progress |
| M9 | Authentication (Argon2id, TOTP MFA), roles, client assignment, audit log |
| M10 | Dashboard |
| M11 | PDF report |
| M12 | Finding review workflow and assessment finalization |
| M13 | Hardening: threat model, generated least-privilege policies, security review |
| M14 | Hosting evaluation and deployment |
| M15 | Documentation, license decision, public release |
