# 0019. Data API, scan worker, and the boundary before user authentication

- **Status:** Accepted; points 1–2 superseded by [ADR 0020](0020-authentication-implementation.md) (M9 added real logins)
- **Date:** 2026-10-07

## Context

M8 adds the HTTP API the dashboard will use and the background worker that runs
scans (ADR 0003). User accounts, MFA and roles arrive in M9. Until then there is no
way to know who is calling the API.

## Decision

1. **The data API works only in development and test.** Every data endpoint depends on
   `current_operator`; with `APP_ENV=production` it answers **503** to every request
   (fail closed). Locally the API is published on `127.0.0.1` only. Health endpoints
   stay available everywhere.
2. **One place for access control.** Every client-owned resource lives under
   `/api/v1/clients/{client_id}/...` and goes through the `client_scope` dependency.
   M9 replaces the development operator with the authenticated user and adds the
   "assigned to this client?" check there, without changing any endpoint. A client the
   caller may not access returns the same **404** as one that does not exist.
3. **Browser-based attacks on the local API are blocked** even without logins:
   - only known host names are served (`API_ALLOWED_HOSTS`), which stops DNS
     rebinding (a web page making the browser call `127.0.0.1:8000`);
   - requests that change data must be `application/json`. A cross-site HTML form
     cannot send JSON, and cross-site JavaScript needs a CORS preflight the API never
     approves. This prevents cross-site request forgery (e.g. a page starting scans);
   - responses carry `nosniff`, `DENY` framing, `no-store` caching and a strict CSP.
4. **Errors reveal nothing internal.** Validation errors do not echo submitted values;
   integrity and constraint errors return fixed messages.
5. **Queue = `scan_jobs` table.** The worker claims the oldest queued job with
   `SELECT ... FOR UPDATE SKIP LOCKED`, so several workers can run safely. A partial
   unique index allows at most one queued or running scan per assessment.
6. **Same scan sequence everywhere.** The worker calls the same `app.scanning`
   functions as the CLI (connect → verify account → collect → evaluate) and saves the
   result and the job's completion in one transaction.
7. **Failures are explained, not dumped.** Jobs store a short code and a
   plain-language message built from the provider error helpers; raw exception text
   is never stored. A read-only guard violation fails the job and is logged as an
   error (a platform bug, never retried).
8. **Liveness.** A running job's heartbeat is refreshed every 30 s by a helper thread.
   A job whose heartbeat is older than `WORKER_STALE_AFTER_SECONDS` (default 15 min) is
   marked failed ("Interrupted"); it is not retried automatically. `SIGTERM` lets the
   current scan finish (Compose allows 2 minutes).
9. **Connection validation stays in the CLI for now.** It contacts the client's cloud
   and needs the same care as a scan; it will become a queued job when the dashboard
   needs it.

## Consequences

- The API is usable from the interactive docs (`/docs`) on a developer's machine, but
  cannot be deployed for real use until M9. This is intentional.
- The production image runs the API by default; a deployment runs the worker from the
  same image with the command `python -m app.worker` (and its own health check).
