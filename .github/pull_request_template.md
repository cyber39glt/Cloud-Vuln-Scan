## What and why

<!-- What does this change, and why? Link the issue. -->

## Checklist

- [ ] Read-only boundary respected: no write, delete, deploy or exploit calls; new cloud calls are reads declared in `required_permissions`
- [ ] Tests added or updated; `.\scripts\dev.ps1 check` passes
- [ ] Migration added for database changes; `dev.ps1 policies` run if checks changed
- [ ] Docs / ADR updated where behaviour or decisions changed
- [ ] No secrets, client data or real account identifiers in code, tests, logs or screenshots
