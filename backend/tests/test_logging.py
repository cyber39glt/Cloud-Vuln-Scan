import json
import logging

import pytest

from app.core.logging import REDACTED, JsonFormatter, redact_text, redact_value


def format_record(message: str, *args, extra: dict | None = None, exc_info=None) -> dict:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, message, args, exc_info)
    for key, value in (extra or {}).items():
        setattr(record, key, value)
    return json.loads(JsonFormatter().format(record))


def test_output_is_structured_json():
    entry = format_record("scan started for %s", "assessment-1", extra={"assessment": "a-1"})

    assert entry["message"] == "scan started for assessment-1"
    assert entry["level"] == "INFO"
    assert entry["logger"] == "test"
    assert entry["assessment"] == "a-1"
    assert "timestamp" in entry


# These are deliberately fake secrets used to prove redaction works. The two lines
# Gitleaks would flag carry an inline `gitleaks:allow` marker; no other exception exists.
@pytest.mark.parametrize(
    "text, secret",
    [
        ("login failed password=hunter2", "hunter2"),
        ('config {"client_secret": "abc123xyz"}', "abc123xyz"),
        ("aws_secret_access_key: wJalrXUtnFEMI/K7MD", "wJalrXUtnFEMI/K7MD"),  # gitleaks:allow
        ("using key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("temp key ASIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"),
        ("db postgresql://admin:s3cr3t@db:5432/x", "s3cr3t"),
        ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
        (
            "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl",  # gitleaks:allow
            "eyJzdWIiOiIxMjM0In0",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
            "MIIEow",
        ),
    ],
)
def test_secrets_in_messages_are_redacted(text, secret):
    redacted = redact_text(text)

    assert secret not in redacted
    assert REDACTED in redacted


def test_sensitive_extra_fields_are_redacted():
    entry = format_record(
        "connecting",
        extra={
            "password": "hunter2",
            "headers": {"Authorization": "xyz", "Accept": "application/json"},
            "external_id": "client-external-id-123",
        },
    )

    assert entry["password"] == REDACTED
    assert entry["headers"]["Authorization"] == REDACTED
    assert entry["headers"]["Accept"] == "application/json"
    assert entry["external_id"] == REDACTED


def test_exception_text_is_redacted():
    try:
        raise RuntimeError("could not connect with password=hunter2")
    except RuntimeError:
        import sys

        entry = format_record("failure", exc_info=sys.exc_info())

    assert "hunter2" not in json.dumps(entry)
    assert "RuntimeError" in entry["exception"]


def test_ordinary_text_is_unchanged():
    text = "Discovered 42 security groups in eu-west-2"

    assert redact_text(text) == text
    assert redact_value({"region": "eu-west-2", "count": 42}) == {
        "region": "eu-west-2",
        "count": 42,
    }
