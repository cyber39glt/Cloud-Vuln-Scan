"""Serves the dashboard (the built React app) from the API process.

Same origin as the API, so the session cookie stays SameSite=Strict and no CORS is
needed. Any path that is not an API route, health check or file returns index.html,
and the React router shows the right page. Only files inside the build directory can
be served (no path traversal).
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_RESERVED_PREFIXES = ("api/", "health", "docs", "openapi.json")


def mount_dashboard(app: FastAPI, dist: Path) -> bool:
    """Serve the dashboard if it has been built. Returns whether it was mounted."""
    index = dist / "index.html"
    if not index.is_file():
        return False
    root = dist.resolve()
    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def dashboard(path: str) -> FileResponse:
        if path.startswith(_RESERVED_PREFIXES):
            raise HTTPException(status_code=404)
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index)

    return True
