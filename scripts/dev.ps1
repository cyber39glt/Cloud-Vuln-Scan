<#
.SYNOPSIS
    Development commands for CloudSecura (Windows PowerShell 5.1+ or PowerShell 7).

.DESCRIPTION
    Wraps the Docker commands you need day to day, so you do not have to remember them.
    Everything runs inside containers: only Docker Desktop and Git are required.

.EXAMPLE
    .\scripts\dev.ps1 up
    .\scripts\dev.ps1 test
    .\scripts\dev.ps1 test -k health
#>
param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "up", "down", "restart", "status", "logs", "test", "lint", "format",
                 "secrets", "check", "build", "reset", "demo", "aws", "migrate",
                 "clients", "assessments", "azure", "users", "webtest", "policies")]
    [string]$Command = "help",

    # Anything after the command is passed through (e.g. extra pytest options).
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$GitleaksImage = "zricethezav/gitleaks:v8.30.1"
$ProdImage = "cloud-vuln-scan-api:local"

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Run an external program and stop if it fails (PowerShell does not do this by itself).
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Program $($Arguments -join ' ')' failed with exit code $LASTEXITCODE"
    }
}

function Assert-DockerRunning {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Start Docker Desktop, wait until it says 'Engine running', then retry."
    }
}

function Initialize-EnvFile {
    $envFile = Join-Path $RepoRoot ".env"
    if (-not (Test-Path $envFile)) {
        Copy-Item (Join-Path $RepoRoot ".env.example") $envFile
        Write-Host "Created .env from .env.example (local development values)." -ForegroundColor Yellow
    }
    # Give this machine its own random APP_SECRET_KEY (encrypts MFA secrets) once.
    $content = Get-Content $envFile -Raw
    if ($content -notmatch "(?m)^APP_SECRET_KEY=\S+") {
        $bytes = New-Object byte[] 48
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $key = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
        $content = $content -replace "(?m)^APP_SECRET_KEY=.*\r?\n?", ""
        Set-Content -Path $envFile -Value ($content.TrimEnd() + "`nAPP_SECRET_KEY=$key`n") -NoNewline
        Write-Host "Generated a random APP_SECRET_KEY in .env (keep it; do not share it)." -ForegroundColor Yellow
    }
}

function Invoke-Compose([string[]]$Arguments) {
    Invoke-Checked "docker" (@("compose") + $Arguments)
}

function Show-Help {
    Write-Host @"
Usage: .\scripts\dev.ps1 <command> [extra args]

  up        Build and start PostgreSQL + API + scan worker, then apply migrations
  down      Stop the containers (database data is kept)
  restart   down, then up
  status    Show running containers and their health
  logs      Follow the API and worker logs (Ctrl+C to stop); 'logs worker' for one
  test      Run the backend test suite inside the container (extra args go to pytest)
  webtest   Type-check and test the dashboard (frontend)
  policies  Regenerate the least-privilege cloud permissions in infra/ (after changing checks)
  lint      Check code style and common mistakes with Ruff
  format    Auto-format and auto-fix code with Ruff
  secrets   Scan the git history for committed secrets with Gitleaks
  check     lint + test + webtest + secrets (what CI runs)
  build     Build the production image ($ProdImage)
  migrate   Apply database migrations (also done automatically by 'up')
  demo      Run the rule engine on sample data (add -json for the full dataset,
            or -save "Demo Client" to store it and try listing/exports)
  clients   Manage clients, e.g.:  clients add "Acme Ltd"   |   clients list
  assessments  Saved results, e.g.:  assessments list --client "Acme Ltd"
                                     assessments show --client "Acme Ltd" --scan <id>
                                     assessments export --client "Acme Ltd" --scan <id>
            (exports are written to backend\exports\ and contain client data)
  aws       AWS connection and assessment tools, e.g.:
              aws external-id
              aws validate --account-id 123456789012 --external-id <id>
              aws connect --client "Acme Ltd" --account-id 123456789012
              aws scan --client "Acme Ltd" --account-id 123456789012 [--regions eu-west-2]
              (use --external-id instead of --client for an unsaved one-off scan)
  azure     Azure connection tools, e.g.:
              azure connect --client "Acme Ltd" --tenant-id <guid> --subscription-id <guid>
              azure validate --client "Acme Ltd" --subscription-id <guid>
              azure scan --client "Acme Ltd" --subscription-id <guid> [--regions uksouth]
  users     User accounts (run on the server), e.g.:
              users create --admin --email you@example.com --name "Your Name"
              users list
              users reset-mfa --email someone@example.com       (lost phone)
              users reset-password --email someone@example.com  (forgotten / locked)
  reset     Stop everything AND delete the local database (asks first)

After 'up':  http://localhost:5173          THE DASHBOARD (log in here; see docs/dashboard.md)
             http://localhost:8000/docs     (interactive API docs, development only)
             http://localhost:8000/health   http://localhost:8000/health/ready
"@
}

function Invoke-Migrations {
    Write-Step "Applying database migrations"
    Invoke-Compose @("run", "--rm", "api", "alembic", "upgrade", "head")
}

function Invoke-Lint {
    Write-Step "Ruff lint"
    Invoke-Compose @("run", "--rm", "--no-deps", "api", "ruff", "check", ".")
    Write-Step "Ruff format check"
    Invoke-Compose @("run", "--rm", "--no-deps", "api", "ruff", "format", "--check", ".")
}

function Invoke-Tests {
    Write-Step "pytest (starts the database if needed)"
    Invoke-Compose (@("run", "--rm", "api", "pytest") + $ExtraArgs)
}

function Invoke-WebTests {
    Write-Step "Dashboard: type-check and tests"
    Invoke-Compose @("run", "--rm", "--no-deps", "web", "sh", "-c",
        "npm ci --no-audit --no-fund && npm run typecheck && npm test")
}

function Invoke-SecretScan {
    Write-Step "Gitleaks secret scan of git history"
    Invoke-Checked "docker" @("run", "--rm", "-v", "${RepoRoot}:/repo", $GitleaksImage,
        "git", "/repo", "--redact", "--no-banner", "--verbose")
}

Push-Location $RepoRoot
try {
    if ($Command -eq "help") { Show-Help; return }

    Assert-DockerRunning
    Initialize-EnvFile

    switch ($Command) {
        "up" {
            Write-Step "Starting containers"
            Invoke-Compose @("up", "--build", "--detach", "--wait")
            Invoke-Migrations
            Write-Host "`nDashboard: http://localhost:5173   (API: http://localhost:8000)" -ForegroundColor Green
            Write-Host "First time? Create your admin account:  .\scripts\dev.ps1 users create --admin --email you@example.com --name `"Your Name`"" -ForegroundColor Green
            Write-Host "Scan worker running: '.\scripts\dev.ps1 logs worker' shows its activity." -ForegroundColor Green
        }
        "down"    { Write-Step "Stopping containers"; Invoke-Compose @("down") }
        "restart" {
            Invoke-Compose @("down")
            Invoke-Compose @("up", "--build", "--detach", "--wait")
            Invoke-Migrations
        }
        "migrate" { Invoke-Migrations }
        { $_ -in "clients", "assessments", "azure", "users" } {
            Invoke-Compose (@("run", "--rm", "api", "python", "-m", "app.cli", $Command) + $ExtraArgs)
        }
        "status"  { Invoke-Compose @("ps") }
        "logs" {
            $services = if ($ExtraArgs.Count -gt 0) { $ExtraArgs } else { @("api", "worker") }
            Invoke-Compose (@("logs", "--follow") + $services)
        }
        "test"    { Invoke-Tests }
        "lint"    { Invoke-Lint }
        "format" {
            Write-Step "Ruff auto-fix and format"
            Invoke-Compose @("run", "--rm", "--no-deps", "api", "ruff", "check", "--fix", ".")
            Invoke-Compose @("run", "--rm", "--no-deps", "api", "ruff", "format", ".")
        }
        "secrets" { Invoke-SecretScan }
        "aws" {
            # Uses the platform AWS identity from .env (see docs/aws-connection.md).
            Invoke-Compose (@("run", "--rm", "api", "python", "-m", "app.cli", "aws") + $ExtraArgs)
        }
        "demo" {
            Write-Step "Rule engine demo on sample AWS + Azure data (no cloud access)"
            $demoArgs = @($ExtraArgs | ForEach-Object { if ($_ -in "-json", "-save") { "-$_" } else { $_ } })
            Invoke-Compose (@("run", "--rm", "api", "python", "-m", "app.demo") + $demoArgs)
        }
        "webtest" { Invoke-WebTests }
        "policies" {
            Write-Step "Regenerating least-privilege cloud permissions in infra/"
            Invoke-Compose @("run", "--rm", "--no-deps", "--volume", "${RepoRoot}/infra:/infra-out",
                "--env", "POLICIES_INFRA_DIR=/infra-out", "api", "python", "-m", "app.policies")
        }
        "check" {
            Invoke-Lint
            Invoke-Tests
            Invoke-WebTests
            Invoke-SecretScan
            Write-Host "`nAll checks passed." -ForegroundColor Green
        }
        "build" {
            Write-Step "Building production image $ProdImage"
            # The dashboard is built inside the image from the frontend folder.
            Invoke-Checked "docker" @("build", "--target", "prod", "--build-context", "frontend=./frontend",
                "--tag", $ProdImage, "./backend")
        }
        "reset" {
            $answer = Read-Host "This deletes the local database volume. Type 'yes' to continue"
            if ($answer -eq "yes") { Invoke-Compose @("down", "--volumes") } else { Write-Host "Cancelled." }
        }
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    Pop-Location
}
