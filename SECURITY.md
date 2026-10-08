# Security Policy

## What this platform is (and is not)

CloudSecura is a **defensive, read-only** cloud security assessment tool.

It **never**:

- modifies, deletes or creates resources in a client environment;
- changes security configuration (no automatic remediation);
- deploys or installs anything into a client environment;
- exploits vulnerabilities or performs destructive or intrusive testing;
- reads business data (for example storage object contents or secret values).

Read-only behaviour is enforced in two independent layers (see
[ADR 0002](docs/decisions/0002-read-only-security-boundary.md)):

1. **Client-side permissions:** clients grant only the read permissions the checks use
   (generated from the code; broader built-in read-only roles are an option), see
   [ADR 0025](docs/decisions/0025-least-privilege-and-security-review.md).
2. **Application-side guard:** the platform allows only an explicit list of read
   operations and blocks every other cloud API call before it is sent, even if the
   granted credentials would allow more (for Azure, checked both first and last in the
   request pipeline, so requests the SDK creates on its own are checked too). Implemented for AWS in
   `backend/app/providers/aws/guard.py` (see [docs/aws-connection.md](docs/aws-connection.md))
   and for Azure in `backend/app/providers/azure/guard.py` (see
   [docs/azure-connection.md](docs/azure-connection.md)).

A contribution that weakens either layer will not be accepted.

## Reporting a vulnerability

The repository is currently **private**. Report suspected vulnerabilities directly
to the maintainers rather than in an issue or pull request. When the project
becomes public, this section will name a private reporting channel (GitHub private
vulnerability reporting).

Please include the affected component, steps to reproduce, and the impact. Do not
include real client data or credentials in a report.

## Supported versions

The project is pre-release. Only the latest commit on the default branch is supported.

## Security practices in this repository

| Practice | How |
|---|---|
| No secrets in git | `.env` is git-ignored; `.env.example` holds placeholders only; Gitleaks scans the full history in CI and via `dev.ps1 secrets` |
| Secrets never logged | Structured JSON logging with automatic redaction of credential-like values; `SecretStr` for passwords; config errors never echo values |
| Safe production config | The production image runs in production mode unless overridden; the app then refuses placeholder or short secrets, insecure cookies and DEBUG logging |
| Minimal exposure | Database not published outside Docker; API bound to `127.0.0.1` in development; API docs disabled in production; no `Server` header |
| Least privilege | Containers run as a non-root user; CI token is read-only |
| Supply chain | Exact dependency versions and hashes pinned in `uv.lock` and `package-lock.json`; CI audits both for known vulnerabilities; the CI token is not persisted |
| Threat model | [docs/threat-model.md](docs/threat-model.md): assets, boundaries, mitigations and the open risks with their milestone |
| Health endpoints | Unauthenticated, so they return fixed statuses only, never error details or versions |

## If a secret is committed

Treat it as compromised even if the commit is removed: **rotate it first**, then
remove it from history. Deleting the file is not enough; it remains in git history.

## Access control (implemented)

| Control | How |
|---|---|
| Accounts | No public sign-up. First administrator via a one-time setup page that needs a code from the server (closed once any user exists); everyone else by single-use, expiring invitation links stored only as hashes ([ADR 0024](docs/decisions/0024-onboarding-and-public-showcase.md)) |
| Passwords | Argon2id; 12+ characters; temporary passwords must be changed at first use |
| MFA | Authenticator app (TOTP) mandatory for every user, no SMS; secrets encrypted at rest; codes single-use; hashed one-time recovery codes |
| Sessions | Server-side; random token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie, stored hashed; 30-minute idle / 12-hour absolute limit; ended on logout, password or MFA change, deactivation |
| Brute force | Account lockout after 5 failures (wrong passwords and wrong authenticator codes together, since the last complete login); per-IP rate limit; identical responses for unknown and wrong accounts |
| CSRF / browser attacks | `SameSite=Strict`, JSON-only POSTs, foreign-Origin refusal, host allowlist |
| Authorization | Admin / Consultant roles; Consultants see only assigned clients (others are "not found"); enforced by one shared dependency on every endpoint, with a test covering every route |
| Dashboard | Same origin as the API (no CORS); session only in an `HttpOnly` cookie; strict Content-Security-Policy (no inline or third-party code); only build files served ([ADR 0021](docs/decisions/0021-dashboard.md)) |
| Browser headers | Strict CSP, no framing, no sniffing, no referrer, Permissions-Policy, Cross-Origin-Opener-Policy; HSTS in production |
| Reports | CSV cells neutralized against formula injection and every field quoted; PDF templates auto-escape client text and the PDF renderer may not fetch any URL or file ([ADR 0022](docs/decisions/0022-pdf-reports.md)) |
| Audit | Append-only log (database refuses changes) of authentication, account changes, data access, scans and exports; never contains secrets |

Details: [ADR 0009](docs/decisions/0009-authentication-and-authorization.md),
[ADR 0020](docs/decisions/0020-authentication-implementation.md),
[docs/users.md](docs/users.md).

## Planned controls (later milestones)

Production deployment ([docs/deployment.md](docs/deployment.md),
[ADR 0026](docs/decisions/0026-production-deployment.md)): HTTPS via Caddy, internal
networks, a restricted database login, keyed integrity signatures, hardened
containers, backups. Still open: keyless platform cloud sign-in (depends on the
hosting choice), SSO through an external identity provider. The full list of open risks is in
[docs/threat-model.md](docs/threat-model.md#residual-risks-accepted-or-deferred). Cloud access uses temporary credentials only (AWS `AssumeRole` with
ExternalId, Azure multi-tenant app with no stored client secrets), see
[ADR 0005](docs/decisions/0005-cloud-access-model.md).
