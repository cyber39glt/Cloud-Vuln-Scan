# 0012. Private repository now, open source later

- **Status:** Accepted
- **Date:** 2026-10-03

## Decision

- The repository stays **private** during development.
- The open-source license is chosen at the public-release stage (M15). Until then,
  all rights are reserved.
- The codebase is developed *as if* public: no secrets or client data in git
  (enforced by Gitleaks across full history), `.env.example` with placeholders,
  clear documentation, ADRs, and no proprietary framework text (ADR 0008).

## Consequences

- Before release: choose a license, re-run a full-history secret scan, review docs
  for internal references, and enable private vulnerability reporting.
