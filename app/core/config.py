"""Application configuration and secrets.

All runtime configuration comes from environment variables (or a local `.env`
file). Secrets are never logged and are never returned by the API.

See `.env.example` for every supported setting.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The placeholder shipped in .env.example. It must never be used in production.
INSECURE_DEFAULT_SECRET = (
    "change-this-in-production-to-a-secure-random-32-byte-hex-string"
)


class Settings(BaseSettings):
    """Typed, validated application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- runtime ---------------------------------------------------------
    environment: Literal["development", "testing", "production"] = "development"
    app_name: str = "FaceTrust Auditor API"
    app_version: str = "0.1.0"
    auto_create_tables: bool = True

    # --- secrets ---------------------------------------------------------
    secret_key: str = Field(default=INSECURE_DEFAULT_SECRET, min_length=32)
    biometric_encryption_key: str = ""

    # --- storage ---------------------------------------------------------
    database_url: str = "sqlite:///./facetrust.db"
    storage_dir: str = "./data/storage"

    # --- sessions / cookies ---------------------------------------------
    session_cookie_name: str = "ft_session"
    csrf_cookie_name: str = "ft_csrf"
    session_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    session_idle_timeout_minutes: int = Field(default=30, ge=1, le=1440)
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict"] = "lax"

    # --- passwords / lockout --------------------------------------------
    password_min_length: int = Field(default=12, ge=8, le=128)
    bcrypt_rounds: int = Field(default=12, ge=4, le=16)
    login_max_failed_attempts: int = Field(default=5, ge=1, le=100)
    login_lockout_minutes: int = Field(default=15, ge=1, le=1440)

    # --- rate limiting (per process, per client IP) ----------------------
    login_rate_limit: int = Field(default=5, ge=1, le=1000)
    login_rate_window_seconds: int = Field(default=60, ge=1, le=3600)
    register_rate_limit: int = Field(default=5, ge=1, le=1000)
    register_rate_window_seconds: int = Field(default=3600, ge=1, le=86400)

    # --- deployment ------------------------------------------------------
    bootstrap_first_user_admin: bool = True
    trust_proxy_headers: bool = False
    cors_origins: str = ""  # comma-separated list, e.g. "http://localhost:5173"

    @field_validator("biometric_encryption_key")
    @classmethod
    def _check_fernet_key(cls, value: str) -> str:
        """Fail fast if a key is supplied but malformed (Fernet format)."""
        if not value:
            return value
        from cryptography.fernet import Fernet

        try:
            Fernet(value.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - re-raised as a clear config error
            raise ValueError(
                "BIOMETRIC_ENCRYPTION_KEY must be a 32-byte url-safe base64 Fernet key"
            ) from exc
        return value

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def insecure_defaults_in_use(self) -> list[str]:
        problems: list[str] = []
        if self.secret_key == INSECURE_DEFAULT_SECRET:
            problems.append("SECRET_KEY is the public placeholder")
        if not self.biometric_encryption_key:
            problems.append("BIOMETRIC_ENCRYPTION_KEY is not set")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE is false (cookies sent over HTTP)")
        return problems

    def validate_for_runtime(self) -> None:
        """Hard-fail unsafe production configuration.

        Development and testing can run with placeholders, but production
        must have real secrets and secure cookies.
        """
        if not self.is_production:
            return

        if self.secret_key == INSECURE_DEFAULT_SECRET:
            raise RuntimeError(
                "Refusing to start in production with the default SECRET_KEY. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if len(set(self.secret_key)) < 10:
            raise RuntimeError("SECRET_KEY is too weak for production")
        if not self.biometric_encryption_key:
            raise RuntimeError("BIOMETRIC_ENCRYPTION_KEY is required in production")
        if not self.cookie_secure:
            raise RuntimeError("COOKIE_SECURE must be true in production (HTTPS only)")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached process-wide settings object."""
    return Settings()
