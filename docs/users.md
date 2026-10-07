# User accounts and logging in

Everyone who uses the platform has their own account, and **everyone must use an
authenticator app** (multi-factor authentication, MFA). There are two roles:

| Role | Can |
|---|---|
| **Admin** | See every client; create clients; create users and assign them to clients; reset passwords and MFA; read the audit log |
| **Consultant** | Work only with the clients assigned to them (connections, assessments, scans, reports) |

Design and security details: [ADR 0009](decisions/0009-authentication-and-authorization.md),
[ADR 0020](decisions/0020-authentication-implementation.md).

## 1. Create the first administrator (once)

There is no sign-up page. On the machine running the platform:

```powershell
.\scripts\dev.ps1 up
.\scripts\dev.ps1 users create --admin --email you@yourcompany.com --name "Your Name"
```

It prints a **temporary password**, shown only once.

## 2. First login

You need an authenticator app on your phone: Microsoft Authenticator, Google
Authenticator, 1Password, Bitwarden, etc. (SMS is not supported, on purpose.)

Until the dashboard exists (M10), use the interactive API page,
**http://localhost:8000/docs**, and "Try it out" on each step:

1. `POST /api/v1/auth/login` with your e-mail and temporary password.
2. `POST /api/v1/auth/mfa/setup` with `{}`. In your app choose "add account" →
   "enter a setup key" and type the `secret` shown (the dashboard will show a QR code).
3. `POST /api/v1/auth/mfa/activate` with the 6-digit code from the app. You receive
   **10 recovery codes**: store them somewhere safe (a password manager). Each works
   once if you lose your phone.
4. `POST /api/v1/auth/password` with the temporary password and a new one (at least
   12 characters; a few random words work well).

Later logins: `login`, then `POST /api/v1/auth/mfa/verify` with `{"code": "123456"}`
(or `{"recovery_code": "...."}`). Log out with `POST /api/v1/auth/logout` and `{}`.

## 3. Add colleagues (admins)

- `POST /api/v1/admin/users` with e-mail, display name and role → a temporary password
  to give them **through a separate channel** (not in the same e-mail as the address).
- `PUT /api/v1/admin/users/{user_id}/clients/{client_id}` assigns a Consultant to a
  client; `DELETE` on the same address removes it.

## When something goes wrong

| Problem | Fix |
|---|---|
| Lost phone | An admin: `POST /api/v1/admin/users/{id}/reset-mfa`. The user sets up MFA again at next login. Or use a recovery code. |
| Forgotten password, or "locked" after 5 wrong tries | Wait 15 minutes (lock), or an admin: `POST /api/v1/admin/users/{id}/reset-password` → new temporary password. |
| Nobody can log in (e.g. the only admin lost their phone) | On the server: `.\scripts\dev.ps1 users reset-mfa --email ...` and/or `users reset-password --email ...`. |
| Someone leaves | `PATCH /api/v1/admin/users/{id}` with `{"is_active": false}`: their sessions end at once. |

Sessions end after 30 minutes without activity, and after 12 hours at most.
Every login, change and data access is recorded in the audit log
(`GET /api/v1/admin/audit-events`), which nobody can edit or delete.
