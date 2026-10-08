# One Dockerfile, two targets:
#   dev   - includes test/lint tools, runs with auto-reload (used by docker-compose.yml)
#   prod  - runtime dependencies only, no source mount, and the built dashboard
#           (used by `dev.ps1 build`). Needs the frontend folder as an extra build
#           context:  docker build --target prod --build-context frontend=./frontend ./backend

# ------------------------------------------------------------------ dashboard build
FROM node:24-alpine AS web
WORKDIR /web
COPY --from=frontend package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY --from=frontend . .
RUN npm run build

# ------------------------------------------------------------------ base
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# System libraries for PDF reports (WeasyPrint: Pango text layout) and one font
# family, so reports look the same on every machine.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# uv: the package manager that installs the exact versions pinned in uv.lock.
RUN pip install --no-cache-dir uv==0.12.22

# Unprivileged user: if the app were ever compromised, the attacker would not be root.
RUN groupadd --system app && useradd --system --gid app --no-create-home app

WORKDIR /app
COPY pyproject.toml uv.lock ./

# ------------------------------------------------------------------ dev
FROM base AS dev

# --frozen: fail rather than silently change versions if uv.lock is out of date.
RUN uv sync --frozen --no-install-project

COPY . .
# The non-root user has no home directory: font caches (PDF reports) go to /tmp.
ENV XDG_CACHE_HOME=/tmp/app-cache
USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ------------------------------------------------------------------ prod
FROM base AS prod

RUN uv sync --frozen --no-dev --no-install-project && pip uninstall -y uv

COPY app ./app
COPY alembic.ini ./
COPY migrations ./migrations
# The dashboard, served by the API at / (settings.web_dist_dir).
COPY --from=web /web/dist ./web
# The non-root user has no home directory: font caches (PDF reports) go to /tmp.
ENV XDG_CACHE_HOME=/tmp/app-cache
# Production mode unless explicitly overridden: the production safety checks (real
# secrets, secure cookies, no API docs) can then never be skipped by omission.
ENV APP_ENV=production
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
