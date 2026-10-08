# 0022. PDF reports: WeasyPrint with escaped templates and no resource fetching

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

M11 adds the client-facing PDF report. ADR 0004 chose WeasyPrint (HTML/CSS → PDF) and
ADR 0007 requires PDF templates to auto-escape. The report contains text that the
client, or an attacker inside the client's account, controls: resource names, tags,
descriptions and evidence values.

## Decision

1. **One dataset.** The PDF is rendered from the same `AssessmentReport` as the JSON,
   CSV and dashboard, built from a hash-verified stored scan. A small view model groups
   findings by issue (F-01, F-02, …, most severe first) and builds the framework
   appendix; it adds no data of its own.
2. **Auto-escaping Jinja2 templates** (`StrictUndefined`, no `|safe`): client text is
   always text, never HTML. A test renders hostile names (`<img src=…>`, template
   syntax) and checks they appear escaped.
3. **No fetching.** WeasyPrint would otherwise load any URL or file the document
   references (a server-side request forgery / local file read risk). The renderer uses
   a fetcher that allows only `data:` URIs: WeasyPrint's protocol allowlist plus an
   explicit check that refuses and logs everything else; no redirects; `base_url` is
   unset. Tests prove `http(s)`, `file` and `ftp` are refused and that no network call
   is made even when such references are injected into the HTML.
4. **Nothing on disk.** The PDF is produced in memory and streamed to the browser, or
   written by the CLI as an owner-only, never-overwritten file.
5. **Honest status.** Until review and finalization exist (M12), every PDF is marked
   **DRAFT** on the cover.
6. **Fixed fonts.** The image installs Pango and the DejaVu font family, so reports look
   the same on every machine. The non-root user's font cache goes to `/tmp`.
7. **Evidence is summarized** (values shortened, at most 25 resources with evidence per
   issue); the JSON export keeps everything.
8. **Rendered on request** in the API (about 7 seconds for 500 findings). Moving large
   renders to the background worker is possible later without changing the template.

## Consequences

- The container image is larger (Pango libraries and fonts).
- Report design changes are made in `backend/app/reporting/templates/` (HTML + CSS).
- Every PDF download is audit-logged as `report.exported` with `format: pdf`.
