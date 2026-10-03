# 0007. One assessment dataset; review layer; finalization

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

Dashboard, PDF, CSV and JSON must never disagree. Consultants must review findings
before delivery, and review actions must be auditable.

## Decision

- One normalized model per assessment (scope, inventory snapshot, check results,
  findings, evidence, framework references) feeds **all** outputs through one report
  builder. JSON is versioned (`schema_version`).
- Raw scan results are **immutable**. A separate review layer records status
  (open, confirmed, false positive, accepted risk), notes, and severity overrides,
  which require a justification. Every review action is audit-logged with reviewer
  and timestamp.
- Assessment lifecycle: **Scanning → In review → Finalized.** Finalizing locks the
  reviewed dataset and records its SHA-256 hash. All outputs use the finalized,
  reviewed dataset. Reopening is possible but audit-logged.
- Findings carry a stable fingerprint (rule ID + resource ID) for future comparison
  between assessments.

## Consequences

- Outputs are consistent and traceable to raw evidence.
- CSV export must neutralize formula injection; PDF templates must auto-escape
  client-controlled text and must not fetch remote URLs.
