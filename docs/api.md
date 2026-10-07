# Using the API (development)

The API is what the dashboard (M10) will use. Until user accounts exist (M9) it works
**only on your own machine** in development; in production it refuses every data
request. See [ADR 0019](decisions/0019-api-worker-and-pre-auth-boundary.md).

## The easy way: interactive docs

1. `.\scripts\dev.ps1 up`
2. Open **http://localhost:8000/docs** in your browser.
3. Click an endpoint → **Try it out** → fill in the fields → **Execute**.

## A complete example

| Step | Request | Body |
|---|---|---|
| 1. Create a client | `POST /api/v1/clients` | `{"name": "Acme Ltd"}` |
| 2. Register an AWS account | `POST /api/v1/clients/{client_id}/connections/aws` | `{"account_id": "123456789012"}` |
| …or an Azure subscription | `POST /api/v1/clients/{client_id}/connections/azure` | `{"tenant_id": "<guid>", "subscription_id": "<guid>"}` |
| 3. Create an assessment | `POST /api/v1/clients/{client_id}/assessments` | `{"connection_id": "<id from step 2>", "name": "Q1 review"}` |
| 4. Request a scan | `POST /api/v1/clients/{client_id}/assessments/{assessment_id}/scans` | `{}` or `{"regions": ["eu-west-2"]}` |
| 5. Follow progress | `GET /api/v1/clients/{client_id}/scan-jobs/{job_id}` | |
| 6. Read the report | `GET /api/v1/clients/{client_id}/scans/{scan_run_id}/report` | |
| …as CSV | `GET /api/v1/clients/{client_id}/scans/{scan_run_id}/report.csv` | |

Step 2 for AWS returns the **ExternalId** and role name the client needs to create the
read-only role ([AWS guide](aws-connection.md)); for Azure the client grants consent
and roles ([Azure guide](azure-connection.md)). Registering contacts no cloud.

Step 4 returns at once with **202 Accepted**: the scan is queued and the worker runs
it in the background. Step 5 shows:

| `status` | Meaning |
|---|---|
| `queued` | Waiting for the worker |
| `running` | In progress; `stage` says where: `connecting` → `collecting` → `evaluating` → `saving` |
| `succeeded` | Done; `scan_run_id` identifies the stored result (use it in step 6) |
| `failed` | `error_message` explains why in plain language; nothing was saved |

Only one scan per assessment can be queued or running at a time. Watch the worker with
`.\scripts\dev.ps1 logs worker`.

## Rules the API enforces

- Requests that create or change something must be JSON (`Content-Type:
  application/json`). Anything else gets **415**.
- Only `localhost` / `127.0.0.1` are accepted as host names (setting
  `API_ALLOWED_HOSTS`). Anything else gets **400**.
- Records of another client are reported as **404 Not found**, exactly like records
  that do not exist.
