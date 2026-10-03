# 0006. Normalized resource model and rule engine

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

Security checks must be modular and testable, and separated from cloud SDK code.
A universal model for every AWS and Azure resource would be over-engineering.

## Decision

- **Collectors** (per provider) are the only code calling cloud APIs. They produce a
  normalized inventory.
- **Resources** use a common envelope (provider, account/subscription, region, type,
  ID, name, tags, selected properties) plus **typed facets** for concepts that really
  span clouds: e.g. `NetworkIngressRule`, `PublicExposure`, `EncryptionState`,
  `PrivilegedAssignment`, `Credential`.
- **Rules** are small Python classes with metadata (ID, title, category, default
  severity, description, risk, remediation, framework references, *required
  permissions*) and an `evaluate(inventory)` method. Rules can be cross-provider
  (operating on facets) or provider-specific.
- Every evaluation yields `PASS`, `FAIL`, `ERROR` (could not evaluate) or
  `NOT_APPLICABLE`. `ERROR` is never treated as a pass.

## Consequences

- Rules are unit-tested with fixture data; no cloud account needed.
- Declared permissions allow generating least-privilege client policies (M13).
