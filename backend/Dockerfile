# One Dockerfile, two targets:
#   dev   - includes test/lint tools, runs with auto-reload (used by docker-compose.yml)
#   prod  - runtime dependencies only, no source mount (used by `dev.ps1 build`)

# ------------------------------------------------------------------ base
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

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
USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ------------------------------------------------------------------ prod
FROM base AS prod

RUN uv sync --frozen --no-dev --no-install-project && pip uninstall -y uv

COPY app ./app
COPY alembic.ini ./
COPY migrations ./migrations
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
