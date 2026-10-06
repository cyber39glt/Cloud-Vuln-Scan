# 0013. Finding granularity, collection gaps and rule purity

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

Implementing the rule engine (M1) required three concrete decisions on top of ADR 0006.

## Decision

1. **One finding per rule per affected resource.** If seven security groups expose
   SSH, that is seven findings. Consultants can review each one separately (e.g. accept
   the risk for one). Dashboards and reports group findings by rule for display.
   Account-level rules produce at most one finding for the account.
2. **Severity scale:** Critical, High, Medium, Low, Informational.
3. **Collection gaps.** Collectors record what they could not read as
   `CollectionGap`s. The engine then:
   - does not run *account-scope* rules whose data has gaps; they report `ERROR`
     ("not evaluated"), since concluding "nothing exists" from missing data is wrong;
   - runs *resource-scope* rules on what was collected and adds one `ERROR` per gap.
4. **Rule isolation.** A rule that raises an exception or returns results for another
   rule or account produces an `ERROR` result; the scan continues. Exception messages
   are not stored, as they may contain collected data.
5. **Rule purity.** Rules may not import cloud SDKs, network, process or database
   modules. This is enforced by an automated test.
6. **Unverified mappings are labelled.** Each framework reference carries `verified`;
   CIS and SOC 2 references stay `false` until checked against the official documents.

## Consequences

- Finding counts reflect affected resources, which reports must explain.
- Every rule that runs leaves a visible outcome (pass, fail, error or not applicable).
- Reports must show "not evaluated" items so that coverage is honest.
