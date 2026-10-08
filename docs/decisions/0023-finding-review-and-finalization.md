# 0023. Finding review and assessment finalization

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

ADR 0007 requires consultants to review findings before a report goes to a client:
confirm them, mark false positives, accept risks, and adjust severity with a reason,
all audit-logged, ending in a final reviewed dataset. Stored scan results are
immutable and hash-verified (ADR 0015), so the review must not change them.

## Decision

1. **A separate review layer.** Decisions live in `finding_reviews`, keyed by
   `(assessment, finding fingerprint)`, never in the scan tables. A decision is one of
   `open`, `confirmed`, `false_positive`, `accepted_risk`, with an optional severity
   override. The report is built from the immutable scan **plus** the decisions.
2. **Justification is enforced twice.** False positive, accepted risk and any severity
   change need a written justification (at least 10 characters): checked by the API
   (422) and by a database CHECK constraint.
3. **History cannot be rewritten.** Every change is also written to
   `finding_review_events` (who, when, before/after, justification); the database
   refuses UPDATE on it. Each change is audit-logged as `finding.reviewed`.
4. **Decisions carry over to rescans.** Because the fingerprint is stable (same
   weakness on the same resource), a rescan of the same assessment shows earlier
   decisions. Only findings that exist in one of the assessment's scans can be reviewed.
5. **Finalization freezes the report.** Finalizing builds the reviewed report for one
   scan (default: the latest), marks it `report_status: "final"`, and stores the JSON
   with its SHA-256 in `assessment_finalizations` (UPDATE refused). It is refused while
   a scan is queued or running, or while any finding is still `open` ("Confirm all
   remaining" exists to make this quick, and is audit-logged). After that the
   assessment is locked: no reviews, no new scans. Exports of that scan come from the
   frozen snapshot, re-verified against its hash on every use; a mismatch is an
   integrity error, never served. PDFs are marked **DRAFT** until then.
6. **Who may do what.** Anyone with access to the client (assigned Consultant or
   Admin) reviews and finalizes. **Reopening** is Admin-only and needs a written
   reason (audit-logged `assessment.reopened`); the earlier snapshot is kept as history.
7. **Report layout.** Report schema 1.1 adds a `review` block to each finding and
   splits the report into `findings` (open and confirmed), `accepted_risks` and
   `false_positives`. Effective severity (after an override) drives ordering, counts and
   ratings; the original severity stays visible. Accepted risks and false positives are
   listed in the PDF appendix with their justification, not hidden.

## Consequences

- No review action touches the client's cloud environment; review is bookkeeping
  inside the platform, consistent with the read-only boundary (ADR 0002).
- Consumers of the JSON contract must handle schema 1.1 (two new lists, `review`).
- Undoing a finalization is deliberate and visible (Admin, reason, audit event), and
  the frozen snapshot remains available for comparison.
