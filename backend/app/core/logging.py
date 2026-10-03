"""Structured JSON logging with secret redaction.

Every log line is a single JSON object, so a log platform can search and filter it
by field. Before anything is written, a redaction step removes values that look like
credentials. This is a safety net: code should still never log secrets deliberately.
"""

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

REDACTED = "[REDACTED]"

# Field names whose values are always hidden, wherever they appear.
_SENSITIVE_KEY = re.compile(
    r"pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|authorization|cookie|session|signature|external[_-]?id",
    re.IGNORECASE,
)

# Patterns that look like secrets inside free-text messages. Each is a
# (regex, replacement) pair; replacements keep enough context to debug.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # key=value / key: value pairs where the key name is sensitive.
    (
        re.compile(
            r"(?i)\b([\w-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
            r"credential|signature)[\w-]*)([\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        rf"\1\2{REDACTED}",
    ),
    # Credentials embedded in URLs: scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/\s@]+):[^@\s/]+@"), rf"\1:{REDACTED}@"),
    # HTTP Authorization header values.
    (re.compile(r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]{8,}"), rf"\1 {REDACTED}"),
    # AWS access key IDs (long-term AKIA, temporary ASIA).
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), REDACTED),
    # JSON Web Tokens (e.g. Azure/Entra access tokens).
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+"), REDACTED),
    # PEM private key blocks.
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        REDACTED,
    ),
]

# Attributes every LogRecord has; anything else was passed via `extra=`.
_STANDARD_RECORD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys() | {"message", "asctime"}
)
# Uvicorn attaches a terminal-coloured duplicate of each message; drop it.
_IGNORED_EXTRAS = frozenset({"color_message"})


def redact_text(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_value(value: Any, key: str | None = None) -> Any:
    """Recursively redact a value; `key` is the field name it was stored under."""
    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [redact_value(v) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    # Unknown objects are converted to text first so they are redacted too.
    return redact_text(str(value))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extras = {
            key: value
            for key, value in vars(record).items()
            if key not in _STANDARD_RECORD_ATTRS
            and key not in _IGNORED_EXTRAS
            and not key.startswith("_")
        }
        entry.update(extras)
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(redact_value(entry), default=str)


def configure_logging(level: str = "INFO") -> None:
    """Send all logs (ours and uvicorn's) to stdout as redacted JSON.

    Containers should log to stdout; the hosting platform collects it.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn installs its own plain-text handlers; route them through ours instead.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
