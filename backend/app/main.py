"""FastAPI application entry point.

Uvicorn (the web server) imports `app` from this module and serves it.
"""

import logging

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import assessments, clients, health
from app.api.security import SecurityMiddleware, install_error_handlers
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
    # Middleware runs outermost-last-added: the host check happens first.
    application.add_middleware(SecurityMiddleware)
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.api_allowed_hosts)
    install_error_handlers(application)

    application.include_router(health.router)
    application.include_router(clients.router)
    application.include_router(assessments.router)

    logger.info("application configured", extra={"environment": settings.app_env})
    return application


app = create_app()
