# 0017. Azure connector: guard design, client access and development identity

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

M6 implements the Azure side of ADR 0005 (multi-tenant Entra application, Reader +
Security Reader at subscription scope) and ADR 0002 (two-layer read-only enforcement).

## Decision

1. **Application guard = azure-core pipeline policy, first in the pipeline.** Every Azure
   SDK client is created through `guarded_client()` with a `ReadOnlyPolicy` that allows a
   request only if it is a GET, to `management.azure.com`, for an allowlisted resource
   type. POST "actions" (e.g. `listKeys`, which returns storage secrets) and data-plane
   hosts (Key Vault, Storage) are always refused. The allowlist is derived from the Azure
   permissions declared by enabled rules (`<Namespace>/<type>/read` only) plus
   `Microsoft.Resources/subscriptions/read`. Tests ensure no SDK client is created any
   other way, and that blocked requests send nothing.
2. **ArmReader** for calls the SDK packages do not cover (subscription details with
   tenant ID), built on azure-core's public `PipelineClient` with the guard first.
3. **Client access:** one multi-tenant app; the client's admin consents (service principal
   created, no access by itself) and assigns `Reader` + `Security Reader` on the
   subscription. **No Microsoft Graph permissions** are requested until a rule needs one.
   The platform stores tenant and subscription IDs only.
4. **Validation fails closed:** the subscription must report the expected tenant and an
   `Enabled` state; a missing value is a failure, never assumed fine.
5. **Development identity:** the app's client secret in the git-ignored `.env`, short
   expiry. **Development only**: production will use workload identity federation
   (keyless), chosen with the hosting platform (M14).
6. **Public Azure cloud only** (`management.azure.com`, `login.microsoftonline.com`).
   Sovereign clouds are out of scope.

## Consequences

- A connection's tenant is fixed at creation; registering the same subscription with a
  different tenant is refused.
- Reader can read most resource configuration. Collectors (M7) must read only the fields
  rules need (data minimization), as with AWS.
- Adding a rule that needs a new Azure permission automatically extends the allowlist; a
  validation probe entry must be added too (enforced by a test).
