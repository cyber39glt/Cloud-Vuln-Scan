# 0020. Authentication and authorization: implementation details

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

ADR 0009 set the requirements (local accounts, Argon2id, mandatory TOTP MFA,
server-side sessions, Admin/Consultant roles, assigned-client isolation, audit log).
M9 implements them and replaces the development-only gate of ADR 0019.

## Decision

**Passwords**
- Argon2id with RFC 9106 parameters (3 passes, 64 MiB, 4 lanes); old hashes are
  upgraded at the next successful login.
- Policy (NIST SP 800-63B style): 12–128 characters, not trivially repetitive, must not
  contain the e-mail name. No forced composition rules or periodic expiry.
- Accounts are created by an administrator (or the `users create` command) with a
  random **temporary password shown once**; it must be changed before any other use.
  There is no self-registration.

**MFA (TOTP)**
- Mandatory for everyone; enrolled at first login. A user who already has MFA
  cannot replace it with only their password: an admin must reset it.
- Secrets are encrypted at rest with Fernet; the key is derived (HKDF-SHA256) from
  `APP_SECRET_KEY`, which production requires (≥32 characters). Development falls back
  to a clearly named development key so a fresh checkout works.
- Codes are accepted for ±1 time step (clock drift) and never twice (last accepted
  step stored). Ten single-use recovery codes, stored as SHA-256 hashes (they are
  random, ~70 bits, so a slow hash is not needed).

**Sessions**
- 256-bit random token in a cookie (`HttpOnly`, `SameSite=Strict`, `Secure`, `Path=/`,
  `__Host-` prefix). Only its SHA-256 hash is stored.
- Login creates a *pending* session (5 minutes) usable only for MFA; MFA success
  replaces it with a new *verified* session (new token: no session fixation).
- Idle timeout 30 minutes, absolute limit 12 hours. Logout deletes the session;
  password change, MFA reset and deactivation delete all of the user's sessions.

**Brute force**
- 5 wrong passwords lock the account for 15 minutes. The response is identical for
  unknown accounts, wrong passwords and locked accounts, and a dummy hash check keeps
  the timing the same.
- 5 wrong MFA codes end the pending session (the password must be entered again).
- 20 login attempts per 5 minutes per IP address (in-memory, per process).

**CSRF** — `SameSite=Strict` cookie; every POST must be JSON (no cross-site form
posts); requests with a foreign `Origin` are refused; the host allowlist stays.

**Authorization**
- One chain of dependencies: `any_session` → `verified_user` → `current_user` →
  `admin_user` / `client_scope`. Admins access every client; Consultants only
  assigned ones, and anything else is **404**. Admin-only: creating clients, user
  management, assignments, the audit log. A test calls every `/api/` route without a
  session and requires 401, so a route cannot be added without authentication.
- The last active administrator cannot be demoted or deactivated, and admins cannot
  remove their own admin access.

**Audit**
- `audit_events` is append-only: database triggers refuse UPDATE, DELETE and TRUNCATE.
  No foreign keys, so entries outlive users and clients.
- Recorded: password and MFA steps (success and failure), lockouts, rate limiting,
  logout, password changes, recovery-code use, user/role/assignment changes, MFA and
  password resets, client/connection/assessment creation, scan requests and results,
  report views and exports — from the API (actor = user), the CLI (actor = `cli`)
  and the worker (actor = `system`). Never passwords, codes, tokens or keys; for
  unknown accounts the attempted e-mail is not stored (it may be a mistyped password).

**Server-side command line** — `users create/list/reset-mfa/reset-password` run with
direct database access, like a database administrator. They bootstrap the first admin
and recover when nobody can log in; every action is audited with actor `cli`.

## Consequences

- The data API now works in production, behind login. The M8 development operator is
  gone.
- The per-IP limit is per process; a shared limit (database or reverse proxy) and
  trusted-proxy client IPs are decided with hosting (M14).
- Changing `APP_SECRET_KEY` makes every enrolled authenticator unusable (all users
  must re-enrol after an admin MFA reset). Key rotation support is future work.
- SSO (OIDC) remains possible via `auth_provider` / `external_subject` (ADR 0009).
