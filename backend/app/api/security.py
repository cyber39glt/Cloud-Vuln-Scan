"""HTTP-level protections and error handling shared by all endpoints (ADR 0019).

- Only known host names are served (TrustedHostMiddleware, configured in main.py):
  blocks DNS rebinding, where a malicious web page makes your browser talk to the
  API on 127.0.0.1.
- Requests that change data must be JSON. Browsers can send "simple" cross-site form
  posts without asking permission; they cannot send JSON cross-site without a CORS
  preflight, which this API never approves. This stops cross-site request forgery.
- Every response carries headers telling browsers not to cache, sniff or frame it.
- Errors never reveal internals: validation errors do not echo the submitted input,
  and unexpected errors return a generic message (details go to the server log).
"""

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.storage.repository import IntegrityViolation, NotFoundError

logger = logging.getLogger(__name__)

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
# The interactive docs page (development only) loads its own scripts and styles.
_DOCS_PATHS = ("/docs", "/openapi.json")


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in UNSAFE_METHODS:
            content_type = request.headers.get("content-type", "").split(";")[0].strip()
            if content_type.lower() != "application/json":
                return JSONResponse(
                    {"detail": "Requests that change data must be sent as application/json."},
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    headers=SECURITY_HEADERS,
                )
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            if name == "Content-Security-Policy" and request.url.path.startswith(_DOCS_PATHS):
                continue
            response.headers.setdefault(name, value)
        return response


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(NotFoundError)
    async def not_found(_: Request, __: NotFoundError) -> JSONResponse:
        # Same answer for "does not exist" and "belongs to another client".
        return JSONResponse({"detail": "Not found."}, status_code=status.HTTP_404_NOT_FOUND)

    @app.exception_handler(IntegrityViolation)
    async def tampered(_: Request, __: IntegrityViolation) -> JSONResponse:
        return JSONResponse(
            {"detail": "This stored scan failed its integrity check and cannot be used."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    @app.exception_handler(IntegrityError)
    async def conflict(_: Request, exc: IntegrityError) -> JSONResponse:
        logger.warning(
            "database constraint rejected a request", extra={"error_type": "IntegrityError"}
        )
        return JSONResponse(
            {"detail": "The request conflicts with existing data."},
            status_code=status.HTTP_409_CONFLICT,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors()
        ]
        return JSONResponse({"detail": errors}, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
