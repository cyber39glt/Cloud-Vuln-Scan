# 0016. Report dataset and JSON/CSV exports

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

ADR 0007 requires one dataset for every output. M5 adds the first two formats.
Exports leave the platform and are opened in other tools, so they are part of the
attack surface (client-controlled text) and must be traceable to their source.

## Decision

1. **One report model** (`AssessmentReport`) is built from a stored, hash-verified scan.
   JSON is that model serialized; CSV is a flat view of its findings. PDF and the
   dashboard will consume the same model.
2. **Traceability:** every report names the client, assessment, scan ID and the scan's
   SHA-256, so any file can be traced to the exact stored result.
3. **Honest coverage:** reports include what was *not evaluated* and standard notes
   stating that the platform does not certify compliance.
4. **Versioned JSON contract:** `schema_version` plus a published JSON Schema; a test
   fails if the schema file and the model disagree.
5. **CSV hardening:** every cell starting with `=`, `+`, `-`, `@`, tab or carriage return
   is prefixed with `'` (OWASP CSV-injection guidance). UTF-8 with BOM for Excel.
6. **Export files:** written only into `exports/` (git-ignored), with names built from
   safe characters only, created owner-readable only (`0600` where the OS supports it),
   and never overwriting an existing file.

## Consequences

- Changing the report model requires regenerating the schema and, for breaking changes,
  a new major `schema_version`.
- Prefixing `-` means a value such as `-1` appears as `'-1` in spreadsheets; no current
  column contains numbers, so this has no practical effect.
