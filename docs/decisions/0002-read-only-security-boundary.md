# 0002. Strict read-only boundary, enforced in two layers

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

The platform holds access to many clients' cloud environments. Any ability to change
those environments would turn a defensive assessment tool into a high-impact attack
path, and would breach client trust. Clients may also, by mistake, grant broader
permissions than requested.

## Decision

The platform is strictly read-only. It never remediates, modifies, deletes, deploys
or exploits. This is enforced in two independent layers:

1. **Client-side permissions:** the platform only ever asks for read-only roles
   (initially AWS `SecurityAudit` + `ViewOnlyAccess`, Azure `Reader` + `Security
   Reader`, minimal Microsoft Graph read permissions), later narrowed to a policy
   generated from what the enabled rules actually need.
2. **Application-side guard:** every cloud SDK client is wrapped so that only an
   explicit allowlist of read operations can be sent. Everything else is blocked
   before the request leaves the platform. Read-looking operations that return
   secrets (for example Azure `listKeys`, a POST) are explicitly blocked.
   A CI test enforces the guard.

The platform also avoids *reading* business data or secrets: no storage object
contents, Key Vault secret values, Lambda environment variables or EC2 user data.

## Consequences

- No remediation features, ever, unless this ADR is explicitly superseded.
- Every new collector must declare its API operations so they can be allowlisted.
- Evidence is minimized and redacted before storage.
