"""Health endpoints used by Docker, load balancers and monitoring.

- /health        "Is the process alive?"  Never touches dependencies, so a database
                 outage does not cause the platform to restart the container.
- /health/ready  "Can it serve real work?"  Checks the database is reachable.

Both are unauthenticated, so they return only a fixed status, never error details,
versions or hostnames.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import Engine

from app.core.database import check_database, get_engine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
def readiness(response: Response, engine: Annotated[Engine, Depends(get_engine)]) -> dict:
    try:
        check_database(engine)
    except Exception as exc:
        # Log only the exception type: driver messages can include hostnames
        # or usernames, and the caller of this endpoint is unauthenticated.
        logger.warning("readiness check failed", extra={"error_type": type(exc).__name__})
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "checks": {"database": "unavailable"}}
    return {"status": "ready", "checks": {"database": "ok"}}
