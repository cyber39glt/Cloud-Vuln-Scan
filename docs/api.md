# Using the API

The API is what the dashboard (M10) will use. Every data request needs a login
(password + authenticator code): see **[User accounts and logging in](users.md)** first.

## The easy way: interactive docs (development)

1. `.\scripts\dev.ps1 up`
2. Open **http://localhost:8000/docs** in your browser.
3. Log in (`/api/v1/auth/login`, then `/api/v1/auth/mfa/verify`); the browser keeps
   the session cookie for the following requests.
4. Click an endpoint → **Try it out** → fill in the fields → **Execute**.

## A complete example

| Step | Request | Body |
|---|---|---|
| 1. Create a client (admins) | `POST /api/v1/clients` | `{"name": "Acme Ltd"}` |
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

- You must be logged in (**401** otherwise). Consultants can use only the clients
  assigned to them; anything else is **404 Not found**, exactly like a record that
  does not exist. Admin-only actions return **403** to Consultants.
- `POST` requests must be JSON (`Content-Type: application/json`; send `{}` when there
  is nothing to send). Anything else gets **415**. Requests from other websites
  (a foreign `Origin` header) get **403**.
- Only `localhost` / `127.0.0.1` are accepted as host names (setting
  `API_ALLOWED_HOSTS`). Anything else gets **400**.
