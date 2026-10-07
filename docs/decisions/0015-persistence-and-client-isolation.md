# 0015. Persistence, client isolation in the database, and immutable results

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

Assessment results must be stored per client, never mix between clients, and stay
trustworthy as evidence. Users and roles do not exist yet (M9).

## Decision

1. **Schema** (SQLAlchemy 2 models, Alembic migrations):
   `clients → cloud_connections → assessments → scan_runs → findings`.
2. **Client isolation in two layers now:**
   - **Database:** every client-owned table carries `client_id`; children reference
     parents with composite foreign keys on `(parent_id, client_id)`. PostgreSQL rejects
     any row linking one client's data to another client's record, whatever the code does.
   - **Application:** all data access goes through `app/storage/repository.py`, whose
     functions require `client_id` and filter by it. Another client's record is reported
     as "not found", revealing nothing.
   - **Later (M9/M13):** PostgreSQL row-level security based on the logged-in user's
     assigned clients, as a third layer.
3. **Frozen scan results:** each scan run stores the complete `AssessmentResult` as JSON
   plus a SHA-256 over a canonical JSON form; the hash is verified on every read. A
   database trigger refuses `UPDATE` on `scan_runs` and `findings`. `DELETE` remains
   possible for data retention and client offboarding (cascades from the client).
   Consultant review (M12) will live in separate tables and never modify stored findings.
4. **Findings are also stored as rows** (copied from the snapshot) so dashboards can
   filter and count efficiently; the snapshot remains the authoritative record.
5. **Migrations are explicit:** applied by `dev.ps1 up`/`migrate` and in CI, never
   silently by the web application at startup. CI fails if models and migrations differ.
6. **ExternalIds are stored in plain text.** They are not credentials on their own
   (ADR 0005); uniqueness is enforced by the database.

## Consequences

- A forgotten client filter in new code still cannot create cross-client links, and
  tests cover cross-client reads for every repository function.
- Correcting a stored scan means running a new scan, never editing the old one.
- Tests use a separate, migrated test database, rolled back after each test.
