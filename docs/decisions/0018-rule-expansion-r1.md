# 0018. Rule expansion R1: identity, storage, database, logging and Defender checks

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

M0–M7 proved the pipeline end to end with four rules. Before building the web platform
(M8–M10), the rule set was expanded so assessments are useful on real client
environments: 9 new AWS rules and 6 new Azure rules (19 in total). New collection was
needed for IAM, S3, RDS, Azure SQL, the Activity Log export and Defender for Cloud.

## Decision

1. **One documented exception to "reads only" in AWS: `iam:GenerateCredentialReport`.**
   The credential report is the only API that shows, per IAM user, whether a password
   and MFA are in use and when access keys were last used. Generating it asks IAM to
   rebuild a report; it changes no configuration, AWS classifies it as a Read action and
   it is part of the AWS-managed `SecurityAudit` policy. The guard keeps a named
   `READ_ONLY_EXCEPTIONS` set containing only this operation; a test fails if the set
   changes, so any addition needs review. Validation does not probe it (probing would
   rebuild the report); the scan reports a gap if it is denied.
2. **Permission names vs. API names.** Rules declare the IAM permission a client must
   grant (`s3:ListAllMyBuckets`); the guard allows SDK operation names
   (`s3:ListBuckets`). The few differences are listed in `OPERATION_FOR_PERMISSION`, and
   a test checks every translated name exists in the AWS SDK.
3. **Never guess public exposure.** S3 bucket-policy exposure relies on AWS's own
   analysis (`GetBucketPolicyStatus.IsPublic`). If AWS does not report it, the bucket is
   a collection gap ("not evaluated"), not "private". A bucket is reported public only
   when its policy or ACL is public **and** the matching Block Public Access setting
   (bucket or account level) does not neutralize it.
4. **Plain ARM GETs for small Azure areas.** Azure SQL, diagnostic settings and Defender
   pricings are read through `ArmReader` (already guarded) instead of three more SDK
   packages. `ArmReader.list` follows `nextLink` pages; each next page still passes the
   guard (host, GET, allowlisted type), so a malicious `nextLink` cannot redirect a
   request elsewhere.
5. **Data minimization.** From the credential report only booleans and dates are kept
   (no access key IDs). From SQL only public network access and firewall ranges. From
   diagnostic settings only whether a destination exists and which categories are
   enabled, not destination resource IDs.
6. **Subscription-wide settings are "global" resources.** They stay in scope when the
   assessment is limited to specific regions.
7. **New framework mappings are `verified = false`**, including NIST CSF, until checked
   against the official documents.

## Consequences

- Client AWS role: the existing `SecurityAudit` + `ViewOnlyAccess` policies already cover
  every new call; the explicit data/secret Deny list is unchanged.
- Client Azure access: `Reader` covers every new call.
- The demo sample data now includes these resource types, so the demo shows 16 findings.
