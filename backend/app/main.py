"""FastAPI application entry point.

Uvicorn (the web server) imports `app` from this module and serves it.
"""

import logging

from fastapi import FastAPI

from app.api import health
from app.core.config import get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    # Interactive API docs are useful in development but reveal the full API
    # surface, so they are switched off in production.
    docs_enabled = not settings.is_production

    application = FastAPI(
        title="Cloud Vuln Scan API",
        description="Read-only cloud security assessment platform for AWS and Azure.",
        version="0.1.0",
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    application.include_router(health.router)

    logger.info("application configured", extra={"environment": settings.app_env})
    return application


app = create_app()
