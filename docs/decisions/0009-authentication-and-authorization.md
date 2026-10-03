# 0009. Local auth, mandatory TOTP MFA, roles, assigned-client isolation

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

V1 serves internal consultancy users only; there is no client portal. The platform
holds read access to many clients' clouds, so account compromise is high-impact.
SSO (e.g. Microsoft Entra ID) is wanted later without a rewrite.

## Decision

**Authentication (built in M9)**
- Local accounts; passwords hashed with **Argon2id**.
- **TOTP authenticator-app MFA is mandatory for every user**, admins included.
  No SMS. One-time recovery codes are stored hashed. MFA setup, verification,
  failures, recovery-code use, reset and disablement are all audit-logged; disabling
  or resetting another user's MFA is an admin action that is itself audited.
- Server-side sessions stored in PostgreSQL, referenced by an `HttpOnly`, `Secure`,
  `SameSite` cookie; idle and absolute timeouts; immediate revocation on logout or
  password/MFA change. CSRF protection on state-changing requests. Login rate
  limiting and lockout.

**Provider boundary for future SSO**
- Users have `auth_provider` and `external_subject` fields. Login produces an internal
  identity; sessions, authorization and audit never depend on how the user logged in.
  Adding OIDC (Entra ID or another IdP) means adding a provider, not changing the rest.

**Authorization**
- Roles: **Admin** (all clients; manage users and client assignments) and
  **Consultant** (only clients assigned to them).
- Enforced **server-side on every endpoint** through a single shared authorization
  dependency; client isolation is a security boundary, not a UI filter. Requests for
  another client's data return "not found" to avoid revealing that it exists.
- Authorization tests cover cross-client access for every endpoint.

**Audit**
- Append-only audit log of authentication events, user/role/assignment changes,
  access to client and assessment data, scans, review actions, finalization and exports.
  Audit entries never contain secrets.

## Consequences

- Every new endpoint must use the shared authorization dependency (enforced by tests).
- Admin bootstrap (the first admin account) will be a one-off command, not a public
  sign-up page.
