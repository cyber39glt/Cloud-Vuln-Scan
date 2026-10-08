import pytest
from pydantic import ValidationError

from app.core.config import Settings


@pytest.fixture(autouse=True)
def _no_settings_from_environment(monkeypatch):
    """The test container receives .env as environment variables (CI changes some of
    them). Remove every variable that maps to a setting, so these tests see the
    defaults; tests that need one set it themselves."""
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


def make_settings(**overrides) -> Settings:
    # _env_file=None: ignore any local .env so tests are deterministic.
    return Settings(_env_file=None, **overrides)


def test_defaults_to_development():
    settings = make_settings()

    assert settings.app_env == "development"
    assert not settings.is_production


def test_password_is_hidden_in_repr():
    settings = make_settings(postgres_password="super-secret-value")

    assert "super-secret-value" not in repr(settings)
    assert "super-secret-value" not in str(settings.postgres_password)


def test_database_url_escapes_special_characters():
    settings = make_settings(postgres_host="db", postgres_password="p@ss:w/rd#1")

    url = settings.database_url

    assert url.host == "db"
    assert url.password == "p@ss:w/rd#1"
    # The string form hides the password by default.
    assert "p@ss" not in str(url)


@pytest.mark.parametrize("password", ["change-me-local-only-1234567890", "short", ""])
def test_production_rejects_weak_or_placeholder_password(password):
    with pytest.raises(ValidationError, match="POSTGRES_PASSWORD"):
        make_settings(app_env="production", postgres_password=password)


def test_validation_errors_do_not_echo_the_password():
    with pytest.raises(ValidationError) as error:
        make_settings(app_env="production", postgres_password="weak-real-pw")

    assert "weak-real-pw" not in str(error.value)


def test_production_rejects_debug_logging():
    with pytest.raises(ValidationError, match="DEBUG"):
        make_settings(
            app_env="production",
            postgres_password="a-long-random-production-secret",
            log_level="DEBUG",
        )


STRONG_KEY = "k" * 16 + "a-long-random-production-key"  # gitleaks:allow  (test-only)


def test_production_accepts_strong_configuration():
    settings = make_settings(
        app_env="production",
        postgres_password="a-long-random-production-secret",
        app_secret_key=STRONG_KEY,
        postgres_owner_user="cloudsecura_owner",
        postgres_owner_password="another-long-random-secret",
    )

    assert settings.is_production
    assert settings.secret_key == STRONG_KEY
    assert settings.owner_database_url.username == "cloudsecura_owner"
    assert settings.database_url.username == "cloudscan"


@pytest.mark.parametrize("owner", ["", "cloudscan"])
def test_production_refuses_connecting_as_the_table_owner(owner):
    with pytest.raises(ValidationError, match="POSTGRES_OWNER_USER"):
        make_settings(
            app_env="production",
            postgres_password="a-long-random-production-secret",
            app_secret_key=STRONG_KEY,
            postgres_owner_user=owner,
        )


def test_development_uses_one_login_for_everything():
    settings = make_settings(postgres_password="dev")
    assert settings.owner_database_url == settings.database_url


@pytest.mark.parametrize("key", ["", "too-short", "change-me" + "x" * 40])
def test_production_requires_a_real_secret_key(key):
    with pytest.raises(ValidationError, match="APP_SECRET_KEY"):
        make_settings(
            app_env="production",
            postgres_password="a-long-random-production-secret",
            app_secret_key=key,
        )


def test_production_requires_secure_cookies():
    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE"):
        make_settings(
            app_env="production",
            postgres_password="a-long-random-production-secret",
            app_secret_key=STRONG_KEY,
            session_cookie_secure=False,
        )


def test_development_falls_back_to_a_marked_development_key():
    assert "development-only" in make_settings(app_env="development").secret_key


def test_rejects_unknown_environment():
    with pytest.raises(ValidationError):
        make_settings(app_env="staging-typo")


def test_reads_values_from_environment(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("POSTGRES_PORT", "6543")

    settings = make_settings()

    assert settings.app_env == "test"
    assert settings.postgres_port == 6543
