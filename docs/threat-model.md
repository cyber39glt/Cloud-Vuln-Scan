# Threat Model

What CloudSecura protects, from whom, how, and what is still open. Written in M13
together with a code-level security review
([ADR 0025](decisions/0025-least-privilege-and-security-review.md)). Update it whenever a
component, data flow or trust boundary changes.

## System in one picture

```
                         Internet / consultancy network
                                      │ HTTPS (TLS at the host, M14)
                                      ▼
  Browser ──► API + dashboard (FastAPI)  ──────────────┐
  (consultant)  • login, MFA, sessions                  │
                • client-scoped data API                ▼
                • reports (PDF/CSV/JSON)          PostgreSQL
                                                  • users, sessions, audit log
  Scan worker ◄── job queue (in PostgreSQL) ──►   • clients, connections
     │                                            • scan results (hash-verified)
     │ read-only API calls                        • reviews, finalized reports
     ▼
  Client AWS account / Azure subscription
  (role or custom role granted by the client)
```

## Assets

| Asset | Why it matters |
|---|---|
| **Client findings and evidence** | A map of each client's weaknesses; in the wrong hands, an attack plan |
| **Client cloud access** | The platform identity plus each client's ExternalId / role assignment |
| **Integrity of results and reports** | Reports drive client decisions and may be used as audit evidence |
| **User accounts** | Admins control access to every client |
| **Secrets** | `APP_SECRET_KEY` (encrypts MFA secrets, derives the setup code), database password, platform cloud credentials |
| **Audit log** | Accountability for every access and change |

## Actors

| Actor | Trust |
|---|---|
| Admin | Trusted; all clients; can reset other users (audited) |
| Consultant | Trusted for assigned clients only |
| Invited person | Untrusted until the invitation is accepted and MFA is set up |
| Anonymous internet user | Untrusted: sees the public showcase page, login, setup (only on a fresh install, with a code) and invitation pages |
| **Client environment** | **Untrusted data source**: resource names, tags, descriptions and API responses can be crafted by anyone with access to that account |
| Cloud provider APIs | Trusted transport (TLS), but responses are treated as data |
| Operator (whoever runs the server) | Trusted; holds the secrets and the database |

## Trust boundaries

1. **Browser ↔ API**: authentication, CSRF, XSS, session theft.
2. **API ↔ database**: client isolation, integrity of stored results.
3. **Worker ↔ client cloud**: the read-only boundary; untrusted responses.
4. **Client data ↔ outputs**: client text rendered in the dashboard, PDF and CSV.
5. **Build ↔ runtime**: dependencies, images, CI.

## Threats and mitigations (STRIDE)

| # | Threat | Mitigation | Where |
|---|---|---|---|
| S1 | Stolen password used to log in | Mandatory TOTP MFA; wrong codes count toward account lockout (5 failures, password or code, since the last complete login); per-IP rate limit | `auth/service.py`, ADR 0020, 0025 |
| S2 | Session hijacking | Random 256-bit token, stored hashed; `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` cookie; idle and absolute expiry; rotation at login | `auth/sessions.py` |
| S3 | Someone claims a fresh installation | Setup page needs a code from the server, derived from `APP_SECRET_KEY` (refused without one); closed once any user exists | `auth/onboarding.py`, ADR 0024 |
| S4 | Forwarded or leftover invitation link | Single use, expiry, revocable, hash stored, token never in a URL the server sees; revoked when its creator loses admin rights | ADR 0024, 0025 |
| T1 | Tampering with stored scans or delivered reports | SHA-256 checked on every read; database triggers refuse UPDATE; a finalized assessment without its snapshot is an integrity error | `storage/repository.py`, `reporting/report.py` |
| T2 | Concurrent requests bypassing "finalized" checks | Finalize, reopen, review and scan start/save lock the assessment row (`SELECT … FOR UPDATE`) | ADR 0025 |
| T3 | CSV formula injection from client text | Formula-start cells prefixed with `'`; every field quoted (also safe in `;`-separator locales) | `reporting/exports.py` |
| T4 | Malicious HTML/CSS in PDF | Auto-escaping templates; the renderer may fetch nothing | ADR 0022 |
| R1 | Denying an action | Append-only audit log (triggers refuse UPDATE/DELETE/TRUNCATE) | ADR 0020 |
| I1 | Consultant reading another client's data | One shared `client_scope` dependency; composite foreign keys; "not found" for unassigned clients; a test covers every route | ADR 0015, 0020 |
| I2 | Platform reading client business data or secrets | Least-privilege permissions without data access; explicit Deny on data/secret reads (AWS); guard blocks data-plane hosts (Azure) | ADR 0025 |
| I3 | Secrets in logs, errors or audit entries | Redaction in logging; fixed error messages; validation errors do not echo input | `core/logging.py`, `api/security.py` |
| I4 | XSS in the dashboard | React escaping, no raw HTML, strict CSP without inline code | ADR 0021 |
| D1 | Login / password spraying | Per-IP rate limit; lockout | `auth/ratelimit.py` |
| D2 | A slow or hostile client environment stalling scans | Bounded timeouts and retries for AWS and Azure; page limits on Azure lists | `providers/` |
| E1 | **The platform changes a client environment** | Layer 1: the client grants only read permissions. Layer 2: guards allow only listed read operations, checked before a request is built (AWS) and both first and last in the request pipeline (Azure) | ADR 0002, 0025 |
| E2 | Consultant performs admin actions | `admin_user` dependency on every admin endpoint; last-admin protection is serialized | ADR 0020, 0025 |
| E3 | Running with development defaults in production | The production image sets `APP_ENV=production`; production refuses placeholder secrets, insecure cookies and debug logging | ADR 0025 |

## Residual risks (accepted or deferred)

These are known and not yet fixed. Each has an owner milestone.

| Risk | Why it remains | Plan |
|---|---|---|
| The app's database role owns the tables (in Docker it is the superuser), so someone with database write access could disable triggers and recompute the unkeyed SHA-256 hashes | Needs a separate, non-owner application role and a keyed hash (HMAC) with the key outside the database | M14 (deployment) |
| Rate limits are per process and use the direct peer address; behind a proxy all users share one bucket | Depends on the hosting choice | M14 |
| No overall time limit per scan; one very large or slow environment can occupy the worker for long | Per-request timeouts and retries are bounded; a hard deadline needs running scans in a separate process | Later |
| AWS S3 region redirects without a region header make botocore call `HeadBucket`, which the guard blocks: that scan fails (safely) | `HeadBucket` needs `s3:ListBucket`, which also lists object names; not granted on purpose | Accepted (rare) |
| With a region restriction, S3 buckets and Azure resources outside the regions are still read, then discarded | The APIs list account-wide | Accepted (configuration only) |
| Lists and exports are not paginated or rate-limited for logged-in users | Authenticated users only; impact is load, not data exposure | Later |
| CI actions and base images are pinned by tag, not by immutable digest | Low risk with a read-only CI token | M15 (before public release) |
| Container runtime hardening (read-only file system, dropped capabilities) | No production deployment yet | M14 |
| An admin can reset another admin's password and MFA | By design (equal admins); every reset is audited | Accepted |
| Real AWS/Azure behaviour of the least-privilege permissions is tested against simulated APIs only | No live account in development | First sandbox test (docs/aws-connection.md, docs/azure-connection.md) |
