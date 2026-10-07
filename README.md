# Cloud Vuln Scan

A **read-only cloud security assessment platform** for security consultancies.
It connects to a client's **AWS** or **Microsoft Azure** environment with read-only
permissions, runs repeatable security checks, collects evidence, and produces
reviewed findings mapped to **CIS**, **NIST CSF 2.0** and **SOC 2**, with
dashboard, PDF, CSV and JSON outputs.

> **Status: early development (milestone M3, AWS scanning).**
> AWS accounts can be assessed from the command line. Azure, storage of results,
> user accounts, the dashboard and reports are not built yet.
> See [the roadmap](docs/architecture.md#roadmap).

> **Security boundary.** This is a defensive assessment tool. It never modifies,
> deletes, deploys to or exploits client environments. See [SECURITY.md](SECURITY.md).

---

## Quick start (Windows)

### 1. Install prerequisites (once)

| Tool | Why | Get it |
|---|---|---|
| **Docker Desktop** | Runs the app and database in containers | https://www.docker.com/products/docker-desktop/ (use the WSL 2 backend) |
| **Git** | Version control | https://git-scm.com/download/win |
| **VS Code** (recommended) | Editor | https://code.visualstudio.com/ |

You do **not** need Python, PostgreSQL or any cloud SDK installed: they all run inside Docker.

### 2. Allow local PowerShell scripts (once)

Windows blocks scripts by default. In PowerShell, run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

This allows scripts you create or clone locally, but still blocks unsigned scripts
downloaded from the internet.

### 3. Start the application

Make sure Docker Desktop is running, then from the repository folder:

```powershell
.\scripts\dev.ps1 up
```

The first run downloads images and installs dependencies (a few minutes). It also
creates your local `.env` file from `.env.example`.

### 4. Check it works

Open in a browser, or use PowerShell:

```powershell
Invoke-RestMethod http://localhost:8000/health         # -> status: ok
Invoke-RestMethod http://localhost:8000/health/ready   # -> status: ready, database: ok
```

Interactive API docs (development only): http://localhost:8000/docs

### 5. Stop it

```powershell
.\scripts\dev.ps1 down
```

---

## Development commands

All commands are run from the repository root as `.\scripts\dev.ps1 <command>`.

| Command | What it does |
|---|---|
| `up` | Build and start PostgreSQL + API in the background |
| `down` | Stop containers (database data is kept) |
| `restart` | `down` then `up` |
| `status` | Show containers and their health |
| `logs` | Follow API logs (Ctrl+C to stop following) |
| `test` | Run the test suite (extra args go to pytest, e.g. `test -k health`) |
| `lint` | Ruff lint + format check |
| `format` | Auto-fix and format code with Ruff |
| `secrets` | Scan git history for committed secrets (Gitleaks) |
| `check` | `lint` + `test` + `secrets`: the same checks CI runs |
| `build` | Build the production image `cloud-vuln-scan-api:local` |
| `demo` | Run the rule engine on sample AWS + Azure data (`demo -json` for the full dataset) |
| `aws external-id` | Generate an ExternalId for a client connection |
| `aws validate --account-id <id> --external-id <id>` | Check an AWS connection works and is read-only ([guide](docs/aws-connection.md)) |
| `aws scan --account-id <id> --external-id <id> [--regions r1,r2] [--json]` | Run a read-only AWS assessment and print the findings |
| `reset` | Stop everything **and delete the local database** (asks first) |

Code changes in `backend/` are picked up automatically while the app is running.
Rebuild (`restart`) only after changing dependencies in `backend/pyproject.toml`.

### Changing dependencies

Dependencies are declared in `backend/pyproject.toml` and pinned exactly in
`backend/uv.lock`. After editing `pyproject.toml`, regenerate the lockfile:

```powershell
docker compose run --rm --no-deps api uv lock
.\scripts\dev.ps1 restart
```

---

## Configuration

All settings come from environment variables. Locally they are read from `.env`
(git-ignored; created from [`.env.example`](.env.example), which documents every setting).

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `development`, `test` or `production` |
| `LOG_LEVEL` | `INFO` | `DEBUG` is refused in production |
| `API_PORT` | `8000` | Port on your computer for the API |
| `POSTGRES_DB` / `POSTGRES_USER` | `cloudscan` | Database name and user |
| `POSTGRES_PASSWORD` | placeholder | Production refuses placeholder or short (<16 chars) values |
| `DB_CONNECT_TIMEOUT_SECONDS` | `3` | Database connection timeout |

In production, secrets are supplied by the hosting platform's secret manager, never a file.

---

## Project structure

```
.
├── backend/                 Python API (FastAPI)
│   ├── app/
│   │   ├── main.py          Application entry point
│   │   ├── api/             HTTP routes (health checks so far)
│   │   ├── core/            Configuration, logging, database
│   │   ├── domain/          Inventory, findings and evidence models
│   │   ├── rules/           Security rules and the rule engine
│   │   ├── frameworks/      CIS / NIST CSF / SOC 2 mappings
│   │   └── providers/aws/   AWS connector: read-only guard, AssumeRole, validation
│   ├── tests/               pytest tests
│   ├── Dockerfile           dev and prod container images
│   ├── pyproject.toml       Dependencies and tool settings
│   └── uv.lock              Exact pinned dependency versions
├── docs/
│   ├── architecture.md      Architecture overview and roadmap
│   └── decisions/           Architecture Decision Records (ADRs)
├── infra/aws/               CloudFormation: client read-only role; sandbox test fixtures
├── scripts/dev.ps1          Windows development commands
├── docker-compose.yml       Local environment: PostgreSQL + API
├── .env.example             Documented configuration template
└── .github/workflows/ci.yml Continuous integration
```

## Documentation

- [Architecture overview](docs/architecture.md)
- [Architecture decisions](docs/decisions/)
- [Writing a security rule](docs/rules.md)
- [AWS connection and sandbox testing](docs/aws-connection.md)
- [Security policy](SECURITY.md)

## License

To be decided before public release (see [ADR 0012](docs/decisions/0012-private-now-open-source-later.md)).
Until then, all rights are reserved.
