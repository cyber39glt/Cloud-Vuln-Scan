<#
.SYNOPSIS
    Development commands for Cloud Vuln Scan (Windows PowerShell 5.1+ or PowerShell 7).

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
                 "secrets", "check", "build", "reset")]
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
}

function Invoke-Compose([string[]]$Arguments) {
    Invoke-Checked "docker" (@("compose") + $Arguments)
}

function Show-Help {
    Write-Host @"
Usage: .\scripts\dev.ps1 <command> [extra args]

  up        Build and start PostgreSQL + API in the background
  down      Stop the containers (database data is kept)
  restart   down, then up
  status    Show running containers and their health
  logs      Follow the API logs (Ctrl+C to stop following)
  test      Run the test suite inside the container (extra args go to pytest)
  lint      Check code style and common mistakes with Ruff
  format    Auto-format and auto-fix code with Ruff
  secrets   Scan the git history for committed secrets with Gitleaks
  check     lint + test + secrets (what CI runs)
  build     Build the production image ($ProdImage)
  reset     Stop everything AND delete the local database (asks first)

After 'up':  http://localhost:8000/health   http://localhost:8000/health/ready
             http://localhost:8000/docs     (interactive API docs, development only)
"@
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
            Write-Host "`nAPI running at http://localhost:8000  (try /health and /health/ready)" -ForegroundColor Green
        }
        "down"    { Write-Step "Stopping containers"; Invoke-Compose @("down") }
        "restart" { Invoke-Compose @("down"); Invoke-Compose @("up", "--build", "--detach", "--wait") }
        "status"  { Invoke-Compose @("ps") }
        "logs"    { Invoke-Compose @("logs", "--follow", "api") }
        "test"    { Invoke-Tests }
        "lint"    { Invoke-Lint }
        "format" {
            Write-Step "Ruff auto-fix and format"
            Invoke-Compose @("run", "--rm", "--no-deps", "api", "ruff", "check", "--fix", ".")
            Invoke-Compose @("run", "--rm", "--no-deps", "api", "ruff", "format", ".")
        }
        "secrets" { Invoke-SecretScan }
        "check" {
            Invoke-Lint
            Invoke-Tests
            Invoke-SecretScan
            Write-Host "`nAll checks passed." -ForegroundColor Green
        }
        "build" {
            Write-Step "Building production image $ProdImage"
            Invoke-Checked "docker" @("build", "--target", "prod", "--tag", $ProdImage, "./backend")
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
