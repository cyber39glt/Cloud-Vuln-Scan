# Report Exports (JSON and CSV)

Exports are generated from a **saved, hash-verified scan**. JSON, CSV, and later the PDF
and dashboard all render the same report dataset (`backend/app/reporting/report.py`),
so they always agree. Decision record:
[ADR 0016](decisions/0016-report-dataset-and-exports.md).

## Create exports

```powershell
.\scripts\dev.ps1 assessments list --client "Acme Ltd"                 # find the scan ID
.\scripts\dev.ps1 assessments export --client "Acme Ltd" --scan <scan-id>
.\scripts\dev.ps1 assessments export --client "Acme Ltd" --scan <scan-id> --format csv
```

Files are written to **`backend\exports\`** in the project folder, named
`<client>_<scan-id-start>_<UTC timestamp>.json|csv`. The folder is git-ignored.

> **Exports contain client data.** Store them in the engagement's secure location and
> delete local copies when no longer needed. Existing files are never overwritten.

No AWS account yet? Store sample data and export it:
```powershell
.\scripts\dev.ps1 demo -save "Demo Client"     # prints a scan ID
.\scripts\dev.ps1 assessments export --client "Demo Client" --scan <scan-id>
```

## JSON

The complete report: source (consultancy, client, assessment, scan ID and its SHA-256),
scope (provider, account, regions), summary (by severity, category and rule), every
finding with evidence and framework references, everything **not evaluated**, every
check result, and standard notes (no compliance claim; meaning of unverified references).

- Versioned with `schema_version` (currently `1.0`).
- Published contract: [`backend/schemas/assessment-report.schema.json`](../backend/schemas/assessment-report.schema.json)
  (JSON Schema 2020-12). Regenerate with `python -m app.reporting.schema`; a test fails
  if it is out of date.

## CSV

One row per finding (per affected resource), most severe first, for spreadsheet analysis.

| Column | Content |
|---|---|
| `finding_id` | Stable ID (same weakness on same resource = same ID across scans) |
| `severity`, `rule_id`, `title`, `category` | Classification |
| `provider`, `account_id`, `region`, `resource_type`, `resource_name`, `resource_id` | What is affected |
| `detail`, `risk`, `recommendation` | Explanation and remediation |
| `cis`, `nist_csf`, `soc2` | Control IDs; `(unverified)` where not yet checked against the official document |
| `evidence`, `evidence_source` | Evidence summary and the API operation it came from |
| `detected_at`, `client`, `assessment`, `scan_id` | Traceability |

- **Encoding:** UTF-8 with a byte-order mark, so Excel on Windows shows all characters.
- **CSV injection protection:** resource names and other text come from the client's
  environment and could be crafted by an attacker. Spreadsheet programs run cells
  beginning with `=`, `+`, `-`, `@`, tab or carriage return as formulas. Every such
  cell is prefixed with `'` so it is shown as text, never executed.
- Items **not evaluated** are not in the CSV (it lists findings); they are in the JSON
  and will be in the PDF.
