# Contributing to CloudSecura

Thank you for helping. CloudSecura is a **defensive, strictly read-only** cloud
security assessment platform; please read [SECURITY.md](SECURITY.md) first.

## The rule that is never negotiable

The platform must never change, delete, deploy into or exploit a client environment.
A contribution that weakens either read-only layer (client-side permissions, or the
guards in `backend/app/providers/*/guard.py`) will not be accepted. New checks may use
**read** operations only, declared in the rule's `required_permissions`; the guards
and the generated client permissions follow from that list
([ADR 0025](docs/decisions/0025-least-privilege-and-security-review.md)).

## Reporting security problems

**Do not open a public issue.** Use GitHub's private vulnerability reporting
(repository → Security → Report a vulnerability). Never include real client data or
credentials in any report, issue or pull request.

## Development setup

Everything runs in Docker; see the [README](README.md#quick-start-windows).

```powershell
.\scripts\dev.ps1 up        # start
.\scripts\dev.ps1 check     # lint + backend tests + dashboard tests + secret scan (what CI runs)
```

On Linux/macOS use the same `docker compose` commands that `scripts/dev.ps1` runs.

## Making a change

1. Open an issue first for anything larger than a small fix, so we can agree on the
   approach.
2. Keep changes focused; add or update tests (`backend/tests`, `frontend/src/test`).
3. Structural decisions get a short ADR in `docs/decisions/` (copy an existing one).
4. Database changes need an Alembic migration (`docs/data-model.md`); CI fails if the
   models and migrations disagree.
5. Adding or changing a check: update `app/frameworks/mappings.toml`, run
   `.\scripts\dev.ps1 policies` to regenerate the client permissions, and document it
   in `docs/rules.md`.
6. `.\scripts\dev.ps1 check` must pass. Then open a pull request using the template.

## Style

- Python: Ruff (`.\scripts\dev.ps1 format`), type hints, small functions, comments
  that explain *why*.
- TypeScript: strict mode, no inline styles (the Content-Security-Policy forbids
  them), no `dangerouslySetInnerHTML`.
- Plain, precise wording in documentation; say what is not done or not verified.

## Licence

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), like the rest of the project.
