"""
SentinelX — Application Configuration
Loads settings from environment variables / .env file via pydantic-settings.
"""

from functools import lru_cache
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration loaded from .env"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- App ---
    APP_NAME: str = "SentinelX"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # --- Database ---
    DATABASE_URL: str = "postgresql+asyncpg://sentinelx:sentinelx_secret@localhost:5433/sentinelx"
    SYNC_DATABASE_URL: str = "postgresql://sentinelx:sentinelx_secret@localhost:5433/sentinelx"

    # --- Redis ---
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- Security / JWT ---
    SECRET_KEY: str = "change-this-to-a-random-64-char-string"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60   # max 60 minutes — enforced by validator below

    # --- Rate Limiting ---
    RATE_LIMIT_AUTH: str = "10/minute"   # applied to /auth/login and /auth/register

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # --- LLM (via LiteLLM) ---
    # llama3-70b-8192  = stable Groq alias (recommended)
    # llama-3.3-70b-versatile = latest Groq alias
    # llama-3.1-70b-versatile = DECOMMISSIONED — do NOT use
    LITELLM_MODEL: str = "groq/llama-3.3-70b-versatile"
    LITELLM_FALLBACK_MODEL: str = "groq/llama-3.3-70b-versatile"
    GROQ_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""

    # --- External APIs ---
    SHODAN_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # --- Tool Execution ---
    TOOL_TIMEOUT_SECONDS: int = 120  # Hard subprocess timeout for Nmap/Nuclei

    # --- ZAP REST ---
    ZAP_BASE_URL: str = "http://zap:8090"
    ZAP_TIMEOUT_SECONDS: int = 600

    # --- Tool binary paths (empty = auto-resolve via PATH) ---
    NMAP_PATH: str = ""
    NUCLEI_PATH: str = ""

    # --- Dev / Mock ---
    MOCK_MODE: bool = False  # Set True on Windows — tool wrappers return structured fake JSON

    # --- Dev tier bypass (never set in prod) ---
    DEV_BYPASS_TIER: bool = False
    DEV_BYPASS_SECRET: str = ""

    # --- Rate Limits ---
    MAX_FREE_SCANS_PER_DAY: int = 3

    @field_validator("SECRET_KEY")
    @classmethod
    def _require_strong_secret(cls, v: str) -> str:
        if v == "change-this-to-a-random-64-char-string":
            import logging
            logging.getLogger("sentinelx.config").warning(
                "SECRET_KEY is set to the default placeholder — set a strong random value in .env"
            )
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("JWT_EXPIRE_MINUTES")
    @classmethod
    def _cap_jwt_expiry(cls, v: int) -> int:
        if v > 60:
            raise ValueError("JWT_EXPIRE_MINUTES must not exceed 60 (security policy)")
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
