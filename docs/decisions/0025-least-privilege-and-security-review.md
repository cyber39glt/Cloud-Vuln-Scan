# 0025. Generated least-privilege permissions and M13 security review

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

M13 hardens the platform before hosting: client permissions narrower than the
AWS-managed and Azure built-in read-only roles, a threat model
([threat-model.md](../threat-model.md)), and a code-level security review.

## Decision 1: least-privilege permissions, generated from the code

The read-only guards already compute exactly which permissions the enabled checks need
(`assessment_permissions()`). `python -m app.policies` (`dev.ps1 policies`) turns that
same list into what clients grant:

- **AWS:** the onboarding template gets a `PermissionSet` parameter. The default,
  `LeastPrivilege`, grants only the 16 read operations the checks use (an inline
  policy written between GENERATED markers; also `infra/aws/least-privilege-policy.json`).
  `AwsManagedReadOnly` keeps the previous SecurityAudit + ViewOnlyAccess option. The
  explicit Deny on data and secret reads applies to both. The template passes cfn-lint.
- **Azure:** a custom role (`infra/azure/assessment-role.json`; per client, the
  onboarding steps print it for the client's subscription) with only the seven
  `.../read` permissions and no data actions. Reader + Security Reader remain as a
  documented alternative.
- A test fails when the generated files are out of date, so a new check cannot ship
  without its permission being added (and clients then see "not evaluated", never a
  silent pass, until they update).

Trade-off: clients must update the role when checks are added; in return the platform
cannot read anything the checks do not need. These permissions have been tested only
against simulated APIs so far; the first live sandbox test must confirm them.

## Decision 2: fixes from the security review

Four independent reviews (authentication, authorization and data, cloud connectors,
outputs and deployment) found no critical issue and no cross-client access. Fixed,
each with a regression test (`tests/test_hardening.py`, `test_azure_connector.py`):

| Finding | Severity | Fix |
|---|---|---|
| The Azure SDK's automatic resource-provider registration (a POST) and redirects were created behind the guard and not checked | High | The guard is installed twice: first and again after the retry policy (last check before sending). Tests prove both requests are now blocked and were sent before |
| A stolen password allowed unlimited authenticator-code guesses (5 per fresh login) | Medium | Wrong codes count toward the account lockout; only a complete login resets the counter; locked accounts refuse codes. **Amends ADR 0020**: lockout now counts password and code failures together |
| Concurrent use of one recovery/TOTP code | Low | The user row is locked while a second factor is checked |
| The production image ran in development mode if `APP_ENV` was missing (public development key, computable setup code) | Medium | The image sets `APP_ENV=production`; first-run setup refuses without `APP_SECRET_KEY` |
| Finalize/review/scan races could change a finalized assessment | Medium | These actions lock the assessment row; a scan finishing after finalization is not saved |
| A finalized assessment whose snapshot was deleted silently showed a draft | Medium | Integrity error instead |
| CSV formula injection in `;`-separator locales | Medium | Every CSV field quoted |
| Invitations outlived their creator's admin rights | Low | Revoked when the creator is demoted or deactivated; acceptance re-checks the creator |
| Two admins demoting each other at once could leave none | Low | Serialized with an advisory lock |
| Unbounded Azure timeouts/retries could stall the worker | Medium | 10 s connect, 60 s read, 3 retries, 300 s per request |
| No HSTS; no Permissions-Policy / COOP | Low | HSTS in production; the other two always |
| CI token left in `.git/config`; `.env*` could enter the dashboard build | Low | `persist-credentials: false`; `.dockerignore` |

Also added: a CI job auditing Python and dashboard dependencies for known
vulnerabilities (both clean at the time of writing).

## Consequences

- Remaining risks are listed with their owner milestone in the threat model (notably
  a non-owner database role and keyed hashes, and proxy-aware rate limiting, in M14).
- A legitimate user who mistypes their password and then their code several times can
  be locked out for 15 minutes; an admin can unlock them with a password reset.
