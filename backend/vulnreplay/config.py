"""Runtime configuration loaded from environment variables (prefix ``VULNREPLAY_``)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Development placeholder only: production start-up rejects it (see assert_safe_for_production).
_INSECURE_DEFAULT_SECRET = "change-me-development-only-secret-key-000"  # noqa: S105  # nosec B105


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNREPLAY_", env_file=".env", extra="ignore")

    environment: str = Field(default="development", description="development | test | production")
    database_url: str = "sqlite:///./vulnreplay.db"
    secret_key: str = _INSECURE_DEFAULT_SECRET
    access_token_minutes: int = 60
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8080"]

    # Bootstrap administrator (only used when no users exist yet).
    admin_email: str | None = None
    admin_password: str | None = None

    # Evidence import limits.
    max_upload_bytes: int = 5 * 1024 * 1024
    max_body_preview_bytes: int = 64 * 1024

    # Controlled execution limits.
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "::1"]
    request_timeout_seconds: float = 10.0
    max_requests_per_execution: int = 200
    min_request_interval_ms: int = 50
    max_response_bytes: int = 2 * 1024 * 1024

    # API rate limiting (per client IP, per minute).
    login_rate_per_minute: int = 10
    api_rate_per_minute: int = 600

    # Optional local LLM (Ollama-compatible). Disabled when unset.
    llm_base_url: str | None = None
    llm_model: str = "llama3.1"
    llm_timeout_seconds: float = 60.0

    @field_validator("environment")
    @classmethod
    def _valid_env(cls, value: str) -> str:
        if value not in {"development", "test", "production"}:
            raise ValueError("environment must be development, test or production")
        return value

    def assert_safe_for_production(self) -> None:
        if self.environment == "production":
            if self.secret_key == _INSECURE_DEFAULT_SECRET or len(self.secret_key) < 32:
                raise RuntimeError("VULNREPLAY_SECRET_KEY must be set to a random value of >= 32 characters")
            if "*" in self.cors_origins:
                raise RuntimeError("Wildcard CORS origins are not allowed in production")


@lru_cache
def get_settings() -> Settings:
    return Settings()
