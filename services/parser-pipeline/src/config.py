"""Configuration for the parser-pipeline service."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_secret(name: str, env_var: Optional[str] = None, default: Optional[str] = None) -> str:
    """Read a secret from /run/secrets/<name>, fall back to env var, then default."""
    p = Path(f"/run/secrets/{name}")
    if p.exists():
        return p.read_text().strip()
    val = os.getenv(env_var or name.upper(), default)
    if val is None:
        raise RuntimeError(f"Secret '{name}' not found and no fallback available")
    return val


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Redis
    redis_host: str = Field(default="redis", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_db: int = Field(default=0, alias="REDIS_DB")
    redis_password_file: Optional[str] = Field(default=None, alias="REDIS_PASSWORD_FILE")

    # OpenSearch
    opensearch_url: str = Field(default="http://opensearch:9200", alias="OPENSEARCH_URL")
    opensearch_user: str = Field(default="admin", alias="OPENSEARCH_USER")
    opensearch_password_file: Optional[str] = Field(default=None, alias="OPENSEARCH_PASSWORD_FILE")

    # GeoIP
    geoip_db_path: str = Field(default="/data/geoip/GeoLite2-City.mmdb", alias="GEOIP_DB_PATH")
    maxmind_license_key: Optional[str] = Field(default=None, alias="MAXMIND_LICENSE_KEY")

    # Worker
    worker_count: int = Field(default=2, alias="WORKER_COUNT")
    batch_size: int = Field(default=100, alias="BATCH_SIZE")

    # Logging / Metrics
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    metrics_port: int = Field(default=8082, alias="METRICS_PORT")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return upper

    def get_redis_password(self) -> Optional[str]:
        if self.redis_password_file:
            p = Path(self.redis_password_file)
            if p.exists():
                return p.read_text().strip()
        try:
            return get_secret("redis_password", "REDIS_PASSWORD")
        except RuntimeError:
            return None

    def get_opensearch_password(self) -> str:
        if self.opensearch_password_file:
            p = Path(self.opensearch_password_file)
            if p.exists():
                return p.read_text().strip()
        return get_secret("opensearch_password", "OPENSEARCH_PASSWORD", "admin")


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
