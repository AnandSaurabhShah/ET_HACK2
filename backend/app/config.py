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

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
