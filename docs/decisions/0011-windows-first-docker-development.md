# 0011. Windows-first, Docker-based developer experience

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

The primary developer uses Windows and is learning Docker. `make` and other
Linux/macOS tooling cannot be assumed.

## Decision

- Everything (Python, PostgreSQL, tools) runs inside Docker. Required on the host:
  Docker Desktop and Git only.
- Day-to-day commands are wrapped in one PowerShell script, `scripts/dev.ps1`
  (works with Windows PowerShell 5.1 and PowerShell 7).
- `.gitattributes` forces LF line endings for files used inside Linux containers.
- The development auto-reloader uses polling, because Windows bind mounts do not
  deliver file-change events to Linux containers.
- CI runs the same `docker compose` commands as local development.

## Consequences

- Behaviour is identical on Windows, macOS, Linux and CI.
- Editor autocomplete is better with a local Python install, but that is optional.
