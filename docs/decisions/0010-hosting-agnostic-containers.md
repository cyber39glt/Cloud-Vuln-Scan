# 0010. Hosting-agnostic containers, environment-based configuration

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

The hosting provider is deliberately undecided. It will be chosen at M14 based on
security, cost, simplicity, maintainability and the consultancy's needs.

## Decision

- The application ships as a standard container image (`backend/Dockerfile`, `prod`
  target). Nothing in the code depends on a specific host.
- All configuration comes from environment variables, validated at startup
  (`app/core/config.py`). Production refuses unsafe settings.
- Logs go to stdout as JSON, to be collected by whatever platform hosts it.
- `/health` (liveness) and `/health/ready` (readiness) follow conventions supported by
  all major container platforms.
- The platform's own cloud identity uses standard SDK credential chains (ADR 0005).

## Consequences

- Moving between hosts is a deployment-configuration change, not a code change.
- Host-specific features (e.g. a particular secret manager) must be used only through
  environment variables or standard interfaces.
