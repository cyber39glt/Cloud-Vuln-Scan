"""TOTP (authenticator app) multi-factor authentication and recovery codes.

- TOTP secrets must be readable to check codes, so they are ENCRYPTED at rest
  (Fernet: AES-128-CBC + HMAC-SHA256) with a key derived from APP_SECRET_KEY.
- A code is accepted for the current 30-second step or one step either side (clock
  drift), and never twice: the last accepted step is stored per user.
- Recovery codes are random, single-use, and stored only as SHA-256 hashes.
"""

import base64
import hashlib
import hmac
import secrets
import time
from urllib.parse import quote

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

STEP_SECONDS = 30
ALLOWED_DRIFT_STEPS = 1
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alike characters


class MfaKeyError(RuntimeError):
    """A stored secret cannot be decrypted (APP_SECRET_KEY changed or data damaged)."""


def _fernet(secret_key: str) -> Fernet:
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"cloud-vuln-scan",
        info=b"totp-secret-encryption-v1",
    ).derive(secret_key.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def new_secret() -> str:
    return pyotp.random_base32(length=32)  # 160 bits, as RFC 4226 recommends


def encrypt_secret(secret: str, secret_key: str) -> str:
    return _fernet(secret_key).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(token: str, secret_key: str) -> str:
    try:
        return _fernet(secret_key).decrypt(token.encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise MfaKeyError("stored MFA secret cannot be decrypted") from exc


def provisioning_uri(secret: str, email: str, issuer: str) -> str:
    """The otpauth:// link an authenticator app reads (usually shown as a QR code)."""
    label = f"{quote(issuer)}:{quote(email)}"
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30"


def verify_code(
    secret: str, code: str, last_used_step: int | None, now: float | None = None
) -> int | None:
    """The time step the code belongs to if it is valid and unused, else None."""
    code = code.strip().replace(" ", "")
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int((now if now is not None else time.time()) // STEP_SECONDS)
    for step in range(current - ALLOWED_DRIFT_STEPS, current + ALLOWED_DRIFT_STEPS + 1):
        expected = totp.at(step * STEP_SECONDS)
        if hmac.compare_digest(expected, code) and (
            last_used_step is None or step > last_used_step
        ):
            return step
    return None


def new_recovery_codes() -> list[str]:
    """Ten codes like 'k7m2-q9xa-4tpz' (about 70 bits of randomness each)."""
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    return code.strip().lower().replace(" ", "").replace("-", "")


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(normalize_recovery_code(code).encode("utf-8")).hexdigest()
