"""HTTP-level protections and error handling shared by all endpoints (ADR 0019).

- Only known host names are served (TrustedHostMiddleware, configured in main.py):
  blocks DNS rebinding, where a malicious web page makes your browser talk to the
  API on 127.0.0.1.
- Cross-site request forgery is blocked three ways: the session cookie is
  SameSite=Strict (never sent with requests started by another site); every POST
  must be JSON (browsers can send "simple" cross-site form posts, but not JSON
  without a CORS preflight, which this API never approves); and a request carrying an
  Origin header from an unknown host is refused.
- Every response carries headers telling browsers not to cache, sniff or frame it.
- Errors never reveal internals: validation errors do not echo the submitted input,
  and unexpected errors return a generic message (details go to the server log).
"""

import logging
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp

from app.storage.repository import IntegrityViolation, NotFoundError

logger = logging.getLogger(__name__)

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# POST is the only changing method a browser sends cross-site without a CORS
# preflight, so every POST must be JSON (send {} when there is nothing to say).
# PUT, PATCH and DELETE always need a preflight, which this API never approves.
JSON_METHODS = frozenset({"POST"})

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
    def __init__(self, app: ASGIApp, allowed_hosts: list[str]) -> None:
        super().__init__(app)
        self.allowed_hosts = {h.lower() for h in allowed_hosts}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin is not None and (urlsplit(origin).hostname or "") not in self.allowed_hosts:
                return JSONResponse(
                    {"detail": "Cross-site requests are not allowed."},
                    status_code=status.HTTP_403_FORBIDDEN,
                    headers=SECURITY_HEADERS,
                )
        if request.method in JSON_METHODS:
            content_type = request.headers.get("content-type", "").split(";")[0].strip()
            if content_type.lower() != "application/json":
                return JSONResponse(
                    {"detail": "POST requests must be application/json (send {} if empty)."},
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
