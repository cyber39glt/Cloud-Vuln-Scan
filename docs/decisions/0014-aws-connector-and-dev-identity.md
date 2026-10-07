# 0014. AWS connector: guard design, client role and development identity

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

M2 implements the AWS side of ADR 0005 (cross-account AssumeRole with ExternalId) and
ADR 0002 (two-layer read-only enforcement). The hosting provider is undecided, so the
platform's own AWS identity in production is not yet known.

## Decision

1. **Application guard = allowlist at the earliest SDK event.** A handler on botocore's
   `before-parameter-build` event refuses any operation not explicitly allowed, before
   the request is built or sent.
   - Platform identity: only `sts:GetCallerIdentity`, `sts:AssumeRole`.
   - Client accounts: the union of AWS permissions declared by enabled rules plus
     `sts:GetCallerIdentity` and `ec2:DescribeRegions`. Only `Describe*`, `List*`, `Get*`
     names are accepted; anything else fails at startup.
   - Tests ensure every boto3 session in the app is created through the guard.
2. **Client role = read-only managed policies + explicit data Deny.** `SecurityAudit` and
   `ViewOnlyAccess`, plus a Deny on actions that read data or secrets. Maximum session
   one hour. The role ARN is built from the account ID the consultant enters, and
   validation confirms the assumed identity is in that account.
3. **Development platform identity = an IAM user that can only `sts:AssumeRole` on the
   assessment role**, with its access key in the git-ignored `.env`. A leaked key on its
   own grants nothing beyond the read-only, data-denied role in accounts that trust it.
   **Development only:** production will use keyless workload identity, chosen at M14.
4. **Validation before scanning.** Platform identity, role assumption, account match,
   one probe per required permission, and a local write attempt that the guard must block.
5. **Commercial AWS partition only** (`arn:aws:`). GovCloud and China are out of scope.

## Consequences

- Adding a rule that needs a new AWS permission automatically extends the allowlist; a
  probe entry must be added too (enforced by tests).
- `lambda:GetFunctionConfiguration` and `lambda:ListFunctions` remain readable by the
  role and can return Lambda environment variables. The platform's allowlist does not
  include Lambda operations; any future Lambda rule must not collect environment values.
- The development access key must be rotated and never reused outside development.
