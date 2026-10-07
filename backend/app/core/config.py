"""Application settings, loaded from environment variables.

All configuration comes from the environment (or a local `.env` file in development),
never from values hard-coded in source. The same container image therefore runs in
development, test and production; only the environment differs.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL

Environment = Literal["development", "test", "production"]

# Placeholder passwords from .env.example must never reach production.
_PLACEHOLDER_PREFIX = "change-me"
_MIN_PRODUCTION_PASSWORD_LENGTH = 16
_MIN_SECRET_KEY_LENGTH = 32
# Used ONLY when APP_SECRET_KEY is empty outside production, so a fresh checkout works.
# Production refuses to start without a real key (see _check_production_safety).
_DEVELOPMENT_SECRET_KEY = "insecure-development-only-key-never-use-in-production"  # noqa: S105


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Validation errors must not echo the rejected values: they can be secrets
        # and would otherwise be printed to the logs at startup.
        hide_input_in_errors=True,
    )

    app_env: Environment = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    postgres_host: str = "localhost"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str = "cloudscan"
    postgres_user: str = "cloudscan"
    # SecretStr hides the value in repr()/str(), so it cannot leak through
    # accidental logging or error messages.
    postgres_password: SecretStr = SecretStr("")
    db_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)

    # The consultancy operating the platform. Appears in client-facing names (the
    # IAM role clients create, session names in their CloudTrail) and later reports.
    consultancy_name: str = Field(default="SubtleTech", pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{1,30}$")

    # AWS. The platform's OWN credentials are deliberately not settings: boto3 reads
    # them from its standard sources (environment variables locally, workload
    # identity when hosted), so this code never handles them (ADR 0005, ADR 0014).
    aws_region: str = Field(default="us-east-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    aws_assessment_role_name: str = Field(
        default="SubtleTechSecurityAssessment", pattern=r"^[\w+=,.@-]{1,64}$"
    )
    aws_session_duration_seconds: int = Field(default=3600, ge=900, le=3600)

    # Azure: the consultancy's multi-tenant Entra application (ADR 0017). The app ID
    # is not a secret. The client secret is for DEVELOPMENT only; production will use
    # keyless workload identity federation.
    azure_client_id: str = Field(
        default="",
        pattern=r"^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$",
    )
    azure_client_secret: SecretStr = SecretStr("")

    # Background worker (M8, ADR 0019).
    worker_poll_seconds: float = Field(default=2.0, ge=0.5, le=60)
    worker_heartbeat_seconds: int = Field(default=30, ge=5, le=300)
    # A running scan whose heartbeat is older than this is treated as interrupted.
    worker_stale_after_seconds: int = Field(default=900, ge=120, le=86400)

    # Authentication (M9, ADR 0009/0020).
    # Encrypts MFA (TOTP) secrets at rest. Any long random string; generate one with
    # .\scripts\dev.ps1 up (done automatically) or `python -c "import secrets;
    # print(secrets.token_urlsafe(48))"`. Changing it invalidates every enrolled MFA.
    app_secret_key: SecretStr = SecretStr("")
    session_idle_minutes: int = Field(default=30, ge=5, le=480)
    session_absolute_hours: int = Field(default=12, ge=1, le=24)
    # Time allowed between entering the password and the MFA code.
    session_pending_mfa_minutes: int = Field(default=5, ge=1, le=15)
    # Cookies are always "Secure" (HTTPS only) in production. Development over plain
    # http://localhost may turn it off.
    session_cookie_secure: bool = True
    max_failed_logins: int = Field(default=5, ge=3, le=20)
    lockout_minutes: int = Field(default=15, ge=1, le=1440)

    # The built dashboard (frontend/dist, copied here in the production image). When
    # missing (development), only the API is served; use the Vite dev server instead.
    web_dist_dir: str = "/app/web"

    # Host names the API answers to. Anything else is rejected, which stops "DNS
    # rebinding" (a web page tricking your browser into calling the local API).
    api_allowed_hosts: list[str] = ["localhost", "127.0.0.1"]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def secret_key(self) -> str:
        return self.app_secret_key.get_secret_value() or _DEVELOPMENT_SECRET_KEY

    @property
    def database_url(self) -> URL:
        """SQLAlchemy URL object. Using URL.create (not string formatting) means
        special characters in the password are escaped correctly."""
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    @model_validator(mode="after")
    def _check_production_safety(self) -> "Settings":
        """Refuse to start in production with an unsafe configuration."""
        if self.is_production:
            password = self.postgres_password.get_secret_value()
            if (
                password.startswith(_PLACEHOLDER_PREFIX)
                or len(password) < _MIN_PRODUCTION_PASSWORD_LENGTH
            ):
                raise ValueError(
                    "POSTGRES_PASSWORD must be a real secret of at least "
                    f"{_MIN_PRODUCTION_PASSWORD_LENGTH} characters in production"
                )
            if self.log_level == "DEBUG":
                raise ValueError("LOG_LEVEL=DEBUG is not allowed in production")
            key = self.app_secret_key.get_secret_value()
            if len(key) < _MIN_SECRET_KEY_LENGTH or key.startswith(_PLACEHOLDER_PREFIX):
                raise ValueError(
                    f"APP_SECRET_KEY must be a random secret of at least "
                    f"{_MIN_SECRET_KEY_LENGTH} characters in production"
                )
            if not self.session_cookie_secure:
                raise ValueError("SESSION_COOKIE_SECURE must be true in production")
        return self


@lru_cache
def get_settings() -> Settings:
    """Load settings once per process."""
    return Settings()
