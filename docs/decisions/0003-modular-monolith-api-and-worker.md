# 0003. Modular monolith: API + worker, PostgreSQL job queue

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

The expected load is a handful of consultants running a few scans a day. Scans make
hundreds of API calls and take minutes, too long to run inside a web request.
Microservices would add operational complexity with no benefit at this scale.

## Decision

- One Python codebase with clear internal module boundaries (a *modular monolith*).
- Two processes from the same image: an **API** process and a **worker** process.
- Scan jobs are queued in a PostgreSQL table and claimed by the worker using
  `SELECT ... FOR UPDATE SKIP LOCKED`. No Redis, Celery or message broker.

## Consequences

- One deployable image, one database: simple to run, back up and secure.
- If scale ever demands it, the queue can be swapped for a broker behind the same
  interface without changing scan code.
- The worker is introduced in M8; M0 contains only the API.
