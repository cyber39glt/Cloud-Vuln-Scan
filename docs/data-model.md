# Data Model

How assessment data is stored. Decision record:
[ADR 0015](decisions/0015-persistence-and-client-isolation.md).

```
users                        consultancy staff (Admin / Consultant), MFA, lockout
  ├─ user_sessions           login sessions (only token hashes stored)
  ├─ mfa_recovery_codes      one-time codes (hashed)
  └─ client_assignments      which clients a Consultant may access
audit_events                 append-only record of security-relevant actions

clients                      one row per consultancy client
  └─ cloud_connections       an AWS account (or Azure subscription) + its ExternalId
       └─ assessments        a named engagement, e.g. "Q1 AWS review"
            ├─ scan_jobs     scan requests queued for the worker, with progress
            ├─ scan_runs     one completed scan: frozen dataset + SHA-256 hash
            │    └─ findings one row per finding, for dashboards and filtering
            ├─ finding_reviews          the current review decision per finding
            │    (finding_review_events: every change, never rewritten)
            └─ assessment_finalizations the frozen, reviewed report + SHA-256
```

| Table | Key columns | Notes |
|---|---|---|
| `users` | `email` (unique, lower-case), `role`, `is_active`, `password_hash` (Argon2id), `mfa_enabled`, `mfa_secret_encrypted`, `failed_login_count`, `locked_until` | `auth_provider` / `external_subject` reserved for SSO ([ADR 0020](decisions/0020-authentication-implementation.md)) |
| `user_sessions` | `token_hash`, `user_id`, `mfa_verified`, `last_seen_at`, `expires_at` | Deleted on logout, password/MFA change, deactivation |
| `mfa_recovery_codes` | `user_id`, `code_hash`, `used_at` | Single use |
| `client_assignments` | `user_id`, `client_id` | Consultant access; admins need none |
| `audit_events` | `occurred_at`, `action`, `outcome`, `actor_*`, `client_id`, `target_*`, `ip_address`, `details` | **Append-only** (UPDATE/DELETE/TRUNCATE refused); no foreign keys so it outlives users and clients |
| `clients` | `id`, `name` (unique, not blank) | |
| `cloud_connections` | `client_id`, `provider`, `account_id`, `external_id` (unique) | One per client and account |
| `assessments` | `client_id`, `connection_id`, `name`, `status` | `draft` → `in_review` (after a scan) → `finalized` (locked; an Admin can reopen with a reason) |
| `scan_jobs` | `client_id`, `assessment_id`, `status`, `stage`, `regions`, `heartbeat_at`, `error_code`, `error_message`, `scan_run_id` | `queued` → `running` → `succeeded` / `failed`; at most one queued or running per assessment ([ADR 0019](decisions/0019-api-worker-and-pre-auth-boundary.md)) |
| `scan_runs` | `client_id`, `assessment_id`, `regions`, `engine_version`, `result` (JSON), `result_sha256` | **Immutable** |
| `findings` | `client_id`, `scan_run_id`, `fingerprint`, `rule_id`, `severity`, `resource_*`, `data` (JSON) | **Immutable**; copied from `result` |
| `finding_reviews` | `client_id`, `assessment_id`, `fingerprint` (unique together), `status`, `severity_override`, `justification`, `updated_by` | `open` / `confirmed` / `false_positive` / `accepted_risk`; justification required (database CHECK) for the last two and any severity change ([ADR 0023](decisions/0023-finding-review-and-finalization.md)) |
| `finding_review_events` | `client_id`, `assessment_id`, `fingerprint`, `actor`, `status`, `previous_status`, `justification` | **Immutable** history of every decision |
| `assessment_finalizations` | `client_id`, `assessment_id`, `scan_run_id`, `report` (JSON), `report_sha256`, `finalized_by` | **Immutable**; the latest one is the final report while the assessment is `finalized` |

## Concepts

- **ORM (SQLAlchemy):** Python classes in `backend/app/storage/models.py` describe the
  tables; the code works with objects instead of writing SQL by hand.
- **Migration (Alembic):** a versioned script in `backend/migrations/versions/` that changes
  the database structure. Every structural change gets a new migration, applied with
  `.\scripts\dev.ps1 migrate` (automatic on `up`). CI fails if the models and
  migrations disagree.
- **Composite foreign key:** a child row points to its parent by `(parent id, client_id)`,
  so the database itself refuses to link data across clients.
- **Canonical hash:** the stored result is serialized with sorted keys and no spaces
  before hashing, so formatting cannot change the hash, but any content change does.

## Rules for code that touches the database

1. Go through `app/storage/repository.py`; pass the `client_id` every time.
2. Never update stored scan runs or findings (the database refuses). Review data goes
   in its own tables (`finding_reviews`, ...).
3. Change structure only through a new Alembic migration:
   ```powershell
   docker compose run --rm api alembic revision --autogenerate -m "describe the change"
   ```
   then **read and correct** the generated file before committing.
