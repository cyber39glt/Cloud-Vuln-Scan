# 0004. Technology stack

- **Status:** Accepted
- **Date:** 2026-10-03

## Decision

| Concern | Choice | Reason |
|---|---|---|
| Language | Python 3.12 | Team familiarity; first-class AWS and Azure SDKs |
| Web framework | FastAPI + Uvicorn | Typed, fast, automatic API docs, simple |
| Configuration | pydantic-settings | Typed, validated settings from environment variables |
| Database | PostgreSQL 17 | Reliable, JSON support, also serves as the job queue |
| DB access | SQLAlchemy 2 (sync) + psycopg 3; Alembic for migrations (M4) | Mature; sync code is simpler to read and debug |
| AWS | boto3 | Official SDK |
| Azure | azure-identity, azure-mgmt-*, Microsoft Graph (minimal) | Official SDKs |
| Frontend (M10) | React + TypeScript, built with Vite | Static SPA: no second server runtime (Next.js not needed) |
| PDF (M11) | WeasyPrint (HTML/CSS → PDF) | Shares styling with the dashboard; templates are easy to edit |
| CSV / JSON | Python standard library / Pydantic | No extra dependencies needed |
| Packaging | uv with `uv.lock` | Exact, hash-pinned versions; fast installs |
| Lint / format | Ruff (incl. bandit security rules) | One fast tool |
| Tests | pytest | Standard |
| Secret scanning | Gitleaks | Scans full git history |

## Consequences

- Dependencies are added only when a milestone needs them; M0 includes only FastAPI,
  Uvicorn, pydantic-settings, SQLAlchemy and psycopg (+ pytest, httpx2, Ruff for dev).
