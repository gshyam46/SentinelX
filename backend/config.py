"""
SentinelX — Application Configuration
Loads settings from environment variables / .env file via pydantic-settings.
"""

from functools import lru_cache
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
    JWT_EXPIRE_MINUTES: int = 1440  # 24 hours

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # --- LLM (via LiteLLM) ---
    LITELLM_MODEL: str = "groq/llama-3.1-70b-versatile"
    GROQ_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""

    # --- External APIs ---
    SHODAN_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # --- Tool Execution ---
    TOOL_TIMEOUT_SECONDS: int = 120  # Hard subprocess timeout for Nmap/Nuclei/ZAP

    # --- Dev / Mock ---
    MOCK_MODE: bool = False  # Set True on Windows — tool wrappers return structured fake JSON

    # --- Rate Limits ---
    MAX_FREE_SCANS_PER_DAY: int = 3

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
