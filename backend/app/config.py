from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = Field(default="development", alias="AEGIS_ENV")
    database_url: str = Field(default="sqlite:///./app/data/aegis.db", alias="AEGIS_DATABASE_URL")
    api_key: str | None = Field(default=None, alias="AEGIS_API_KEY")
    cors_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        alias="AEGIS_CORS_ORIGINS",
    )
    ingest_rate_limit_per_minute: int = Field(default=180, alias="AEGIS_INGEST_RATE_LIMIT_PER_MINUTE")
    high_blast_radius_threshold: int = Field(default=6, alias="AEGIS_HIGH_BLAST_RADIUS_THRESHOLD")
    perimeter_block_cooldown_seconds: int = Field(default=900, alias="AEGIS_PERIMETER_BLOCK_COOLDOWN_SECONDS")
    demo_background_enabled: bool = Field(default=False, alias="AEGIS_DEMO_BACKGROUND_ENABLED")
    predictive_risk_threshold: float = Field(default=0.58, alias="AEGIS_PREDICTIVE_RISK_THRESHOLD")
    genai_provider: str = Field(default="ollama", alias="AEGIS_GENAI_PROVIDER")
    genai_endpoint: str = Field(default="http://127.0.0.1:11434/api/generate", alias="AEGIS_GENAI_ENDPOINT")
    genai_model: str = Field(default="aegis-cni:latest", alias="AEGIS_GENAI_MODEL")
    genai_api_key: str | None = Field(default=None, alias="AEGIS_GENAI_API_KEY")
    genai_timeout_seconds: float = Field(default=30.0, alias="AEGIS_GENAI_TIMEOUT_SECONDS")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
