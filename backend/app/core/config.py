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

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

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
        return self


@lru_cache
def get_settings() -> Settings:
    """Load settings once per process."""
    return Settings()
