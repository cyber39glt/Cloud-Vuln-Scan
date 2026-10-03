# 0005. Cloud access: AWS AssumeRole + ExternalId, Azure multi-tenant app

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

Scans run on the hosted platform. Consultants' Windows workstations must not hold
cloud SDKs or client credentials. Storing long-lived client secrets would make the
platform a far more valuable target. The hosting provider is not yet chosen
(ADR 0010).

## Decision

**AWS.** The client creates a read-only IAM role (from a CloudFormation template we
provide) that trusts only the platform's own AWS identity and requires a unique,
platform-generated **ExternalId** per client connection. The platform calls STS
`AssumeRole` and receives temporary credentials (about 1 hour). We store only the role
ARN and ExternalId. ExternalId prevents the "confused deputy" problem, where another
party tricks the platform into using a role it should not.

**Azure.** The consultancy owns one **multi-tenant Entra application**. A client
administrator consents to it in their tenant and assigns `Reader` + `Security Reader`
on the subscription; Microsoft Graph read permissions are requested only for Entra ID
checks. The platform authenticates as its own application. We store only tenant and
subscription IDs, no client secrets.

**Platform identity is hosting-agnostic.** The platform's own AWS/Azure identity is
obtained through the SDKs' standard credential chains (boto3 default chain,
`azure-identity` `DefaultAzureCredential`). Locally that is the developer's sandbox
credentials; when hosted it can be workload identity federation, IAM Roles Anywhere or
a secret manager. This is a configuration change, not a code change.

## Consequences

- Clients revoke access by deleting the role or app consent.
- Some Entra checks (MFA registration, sign-in activity) require Entra ID P1/P2; when
  unavailable they are reported as "not evaluated".
- The platform's own identity is the highest-value secret and must be protected
  accordingly (short sessions, secret manager, audit).
