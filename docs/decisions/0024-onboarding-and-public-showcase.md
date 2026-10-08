# 0024. Getting people in without public sign-up; public showcase page; redesign

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

The owner asked for a single showcase page of the features (in the style of OpenVAS /
Greenbone), a premium look, their X handle (@cyber39glt) on the dashboard, and, at
first, for the login to be removed. The platform stores each client's weaknesses and
can start scans with the platform's cloud credentials, so removing the login would
expose an attack plan for every client and make the audit trail meaningless. Public
sign-up has the same problem, plus spam and the need for e-mail verification.

The real friction was elsewhere: the first administrator had to be created on the
command line, and colleagues received temporary passwords that had to be passed on.

## Decision

1. **The login stays; there is no public sign-up.** Accounts are created only by an
   administrator, as before (ADR 0009).
2. **Public showcase page** at `/` for visitors who are not logged in: features,
   how it works, the checks, the security boundary, a sample illustration (labelled
   as such) and the X handle. It contains **no client data**; its only API call asks
   whether first-run setup is still open.
3. **First-run setup in the browser** (`/setup`), open only while there are no users.
   It needs a **setup code** shown by `users setup-code` on the machine running the
   platform, so a stranger who reaches a fresh installation first cannot claim it.
   The code is derived from `APP_SECRET_KEY` (HMAC), so every process agrees on it
   without storing it, and it is **never logged**. Creation is serialized with a
   database lock; once any user exists, setup is closed for good. Failed attempts are
   audit-logged and share the login rate limit.
4. **Invitation links** replace temporary passwords in the dashboard. An admin
   creates an invite (e-mail, name, role); the link is
   `<site>/invite#<random token>`. The token is in the `#fragment`, which browsers never
   send to servers, so it does not appear in access logs; the page sends it in a JSON
   body and removes it from the address bar. Only its SHA-256 hash is stored. Links
   work once, expire (`INVITE_VALID_HOURS`, default 48), can be revoked, and a new
   invite for the same address revokes the previous one. Nothing is e-mailed: the admin
   passes the link on. After accepting, the person must set up MFA exactly as at a first
   login. Every step is audit-logged (`invite.created`, `invite.revoked`,
   `invite.accepted`, `setup.completed`). Temporary passwords remain for resets and the
   command line.
5. **Redesign:** sidebar layout, dark theme by default with a light/dark switch
   (remembered per browser), dashboard charts (findings by severity, most exposed
   assessments), and the X handle in the footer of every page. Severity colours were
   checked for colour-blind separation in both themes; severity is always shown with
   its name too, never by colour alone. The Inter font is bundled with the dashboard
   (SIL Open Font License), so the strict Content-Security-Policy is unchanged: no
   third-party requests.

## Consequences

- Five public endpoints (setup status, setup, invite lookup, invite accept, login);
  the "every route requires a session" test lists them explicitly.
- A forwarded invitation link lets whoever holds it create that account until it is
  used or expires; admins should send links through a trusted channel and revoke
  unused ones.
- Changing `APP_SECRET_KEY` changes the setup code (and, as before, invalidates MFA
  enrolments).
