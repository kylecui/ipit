"""
Configuration management for Threat Intelligence Reasoning Engine.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Keys
    abuseipdb_api_key: Optional[str] = Field(default=None, env="ABUSEIPDB_API_KEY")
    otx_api_key: Optional[str] = Field(default=None, env="OTX_API_KEY")
    greynoise_api_key: Optional[str] = Field(default=None, env="GREYNOISE_API_KEY")
    vt_api_key: Optional[str] = Field(default=None, env="VT_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, env="SHODAN_API_KEY")

    # Cache settings
    cache_ttl_hours: int = Field(default=24, env="CACHE_TTL_HOURS")

    # HTTP settings
    http_timeout_seconds: int = Field(default=15, env="HTTP_TIMEOUT_SECONDS")
    max_retries: int = Field(default=2, env="MAX_RETRIES")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
