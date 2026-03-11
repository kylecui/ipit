"""
Configuration management for Threat Intelligence Reasoning Engine.

v2.0: Per-source API key fields removed. Plugins resolve their own
API keys from environment variables declared in plugin metadata.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Cache settings
    cache_ttl_hours: int = Field(default=24, env="CACHE_TTL_HOURS")

    # HTTP settings
    http_timeout_seconds: int = Field(default=15, env="HTTP_TIMEOUT_SECONDS")
    max_retries: int = Field(default=2, env="MAX_RETRIES")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # Language
    language: str = Field(default="en", env="LANGUAGE")

    # LLM settings (for narrative report generation)
    llm_api_key: Optional[str] = Field(default=None, env="LLM_API_KEY")
    llm_model: str = Field(default="gpt-4o", env="LLM_MODEL")
    llm_base_url: str = Field(default="https://api.openai.com/v1", env="LLM_BASE_URL")

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # v2.0: plugins read API keys directly from env


# Global settings instance
settings = Settings()
