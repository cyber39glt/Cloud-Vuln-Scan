"""Password hashing (Argon2id) and the password policy.

Argon2id is the algorithm recommended by OWASP and RFC 9106 for password storage: it
is deliberately slow and memory-hard, so stolen hashes are expensive to crack. The
hash string contains the algorithm, parameters and a random salt.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# RFC 9106 "second recommended" option: 3 passes, 64 MiB memory, 4 lanes.
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

# Verified against when the e-mail address is unknown, so a login attempt takes the
# same time whether or not the account exists (no user enumeration by timing).
_DUMMY_HASH = _hasher.hash("dummy password for constant-time failure")


class WeakPassword(ValueError):
    """The password does not meet the policy. The message is safe to show."""


def check_policy(password: str, email: str = "") -> None:
    """NIST SP 800-63B style: length matters, composition rules do not."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise WeakPassword(f"Use at most {MAX_PASSWORD_LENGTH} characters.")
    if len(set(password)) < 4:
        raise WeakPassword("The password is too repetitive.")
    local_part = email.split("@")[0].lower()
    if local_part and len(local_part) >= 4 and local_part in password.lower():
        raise WeakPassword("The password must not contain your e-mail name.")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and bool(password_hash)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the hash uses older parameters: re-hash at the next successful login."""
    return _hasher.check_needs_rehash(password_hash)
