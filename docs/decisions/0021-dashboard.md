# 0021. Dashboard: same-origin React app with a strict Content-Security-Policy

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

M10 adds the web dashboard on top of the API (ADR 0004 chose React + TypeScript
built with Vite as a static single-page app). Its security depends on how it is
served and how it talks to the API.

## Decision

1. **Same origin.** In production the API process serves the built files (`/` and
   `/assets/*`); in development Vite serves them and forwards `/api` to the API. The
   browser therefore only ever talks to one origin: the `SameSite=Strict` session
   cookie works, and the API needs **no CORS** (cross-origin requests stay refused).
2. **No secrets in the browser.** The session is the `HttpOnly` cookie from ADR 0020;
   the dashboard never reads or stores a token. Nothing is kept in `localStorage`.
3. **Strict CSP for dashboard pages:** `default-src 'self'; script-src 'self';
   style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none';
   base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. No inline scripts or
   styles (the build emits files only; charts are SVG attributes, not inline styles);
   the MFA QR code is generated in the browser as a `data:` image, so the secret never
   goes to a third party. API responses keep `default-src 'none'`.
4. **Only the build directory is served**, with a path-traversal check; unknown paths
   return `index.html` for client-side routing, but `/api/*`, `/health` and `/docs`
   never fall back to it. Hashed assets are cached; everything else is `no-store`.
5. **One API module** (`src/api.ts`) sends every POST as JSON (the CSRF rule of ADR
   0019/0020) and turns a 401 into "session ended" for the whole app.
6. **Minimal dependencies:** React, React Router, `qrcode`; no UI framework. Pinned
   with `package-lock.json`, installed with `npm ci`.
7. **Overview endpoint** `GET /api/v1/overview` returns, client-scoped, the latest
   scan's severity counts and any running scan for every visible assessment, in one
   request.
8. **Production image** builds the dashboard in a Node stage (extra build context
   `frontend`) and copies only `dist/` into the Python image: no Node at runtime.

## Consequences

- One deployable image still serves API, dashboard and (with another command) the
  worker.
- New UI code must not use inline styles or scripts; the CSP would block them (an
  end-to-end browser check found no CSP violations at release).
- Scan progress uses polling every 2 seconds while a scan runs; push updates are not
  needed at this scale.
