from typing import Literal, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis LLM Security Gateway & Privacy Firewall"
    VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "test", "production"] = "development"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./aegis_gateway.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_ENABLED: bool = True

    # Security
    ADMIN_API_KEY: str = "aegis_admin_secret_super_secure_key_123"
    AUDIT_HMAC_SECRET: str = "aegis_hmac_secret_for_audit_log_tamper_evidence"

    # LLM Provider
    PROVIDER_MODE: Literal["mock", "openai"] = "mock"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_API_KEY: Optional[str] = None
    PROVIDER_TIMEOUT_SECONDS: float = 30.0

    # Gateways thresholds
    DEFAULT_RATE_LIMIT_RPM: int = 60
    DEFAULT_DAILY_TOKEN_BUDGET: int = 100_000
    PROMPT_INJECTION_BLOCK_THRESHOLD: float = 0.70
    PROMPT_INJECTION_WARN_THRESHOLD: float = 0.40

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
