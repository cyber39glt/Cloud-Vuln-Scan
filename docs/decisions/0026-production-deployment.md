# 0026. Production deployment: one server, Caddy, restricted database login, keyed integrity

- **Status:** Accepted (the hosting provider itself is still to be chosen: [hosting.md](../hosting.md))
- **Date:** 2026-10-08

## Context

M14 prepares production. ADR 0010 requires the deployment to be hosting-agnostic.
The M13 threat model left open: the application connected to the database as the
table owner (it could disable the triggers protecting history), result hashes were
unkeyed, rate limiting used the proxy's address, and containers had no runtime
hardening.

## Decision

1. **One Linux server running Docker Compose** (`deploy/compose.prod.yml`), the same
   on any provider. At this size it is the simplest thing that is secure; it can move
   to a managed container service later without code changes.
2. **Caddy** terminates HTTPS with automatic Let's Encrypt certificates and redirects
   HTTP. It is the only container with published ports.
3. **Network isolation:** the API and database sit on internal Docker networks without
   internet access; only the worker (cloud APIs) and Caddy (certificates) can reach the
   internet. The API trusts `X-Forwarded-For` only from Caddy's fixed address, so the
   rate limiter and the audit log see real client addresses.
4. **Two database logins.** The owner runs migrations and backups. The API and worker
   use a restricted login (`app/storage/dbroles.py`, re-applied on every start) that
   can read and write ordinary rows but cannot change the schema, disable triggers,
   set `session_replication_role`, or UPDATE/DELETE audit events, scan results,
   findings, review history or finalized reports. Production refuses to start if the
   application login is the owner. The owner's password is given only to the
   migration and backup containers.
5. **Keyed integrity.** Stored scans and finalized reports carry an HMAC-SHA256
   (key derived from `APP_SECRET_KEY`) over record ID, client, related IDs and content
   hash (migration 0007). Someone who can write to the database but lacks the
   application secret cannot forge a record or move one to another row or client.
6. **Container hardening:** read-only root file systems, no Linux capabilities, no
   privilege escalation, non-root users, memory limits, log rotation, restart policies.
7. **Backups:** a container writes a compressed `pg_dump` daily and keeps 14 days;
   operators copy them off the server. The restore procedure was tested end to end.
8. **CI** starts the production stack with a local certificate and checks HTTPS,
   headers, isolation, the restricted login and saving a scan (`scripts/prod-smoke.sh`).

## Consequences

- `APP_SECRET_KEY` must never change after go-live (MFA secrets and stored signatures
  depend on it); it is backed up with `deploy/.env`.
- One API process: the in-memory rate limiter is exact. Scaling out later needs a
  shared limiter.
- Keyless platform sign-in to AWS/Azure depends on the host (server role / managed
  identity) and follows the hosting choice.
