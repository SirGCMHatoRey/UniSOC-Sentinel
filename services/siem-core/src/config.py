"""
Configuration for the siem-core service.

Reads from environment variables with sensible defaults, and resolves
secrets from Docker secret files at /run/secrets/.
"""

from __future__ import annotations

import os
from functools import cached_property
from pathlib import Path

from pydantic_settings import BaseSettings


def get_secret(
    name: str,
    env_var: str | None = None,
    default: str | None = None,
) -> str:
    """
    Read a secret from a Docker secrets file, falling back to an environment
    variable and then to an explicit default.

    Args:
        name:    Secret name — looked up at /run/secrets/<name>.
        env_var: Environment variable to fall back to (defaults to NAME.upper()).
        default: Final fallback value; if None and no source found, raises.

    Returns:
        The resolved secret value, stripped of surrounding whitespace.

    Raises:
        RuntimeError: When the secret cannot be resolved from any source.
    """
    p = Path(f"/run/secrets/{name}")
    if p.exists():
        return p.read_text().strip()
    val = os.getenv(env_var or name.upper(), default)
    if val is None:
        raise RuntimeError(f"Secret '{name}' not found")
    return val


class Settings(BaseSettings):
    """
    Service settings resolved from environment variables.

    All fields correspond 1:1 to the documented environment variables.
    """

    # PostgreSQL connection
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "siem"
    postgres_db: str = "siem"
    postgres_password_file: str = "/run/secrets/postgres_password"

    # Redis connection
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password_file: str = "/run/secrets/redis_password"

    # OpenSearch connection
    opensearch_url: str = "http://opensearch:9200"
    opensearch_user: str = "admin"
    opensearch_password_file: str = "/run/secrets/opensearch_password"

    # JWT / Auth
    jwt_secret_file: str = "/run/secrets/jwt_secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # CORS
    cors_origins: str = "http://localhost,https://localhost"

    # Observability
    log_level: str = "INFO"
    workers: int = 4

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    # ------------------------------------------------------------------
    # Computed helpers (not loaded from env)
    # ------------------------------------------------------------------

    @cached_property
    def postgres_password(self) -> str:
        """Resolve the PostgreSQL password from the configured secret file."""
        secret_path = Path(self.postgres_password_file)
        if secret_path.exists():
            return secret_path.read_text().strip()
        val = os.getenv("POSTGRES_PASSWORD")
        if val:
            return val
        raise RuntimeError("postgres_password secret not found")

    @cached_property
    def redis_password(self) -> str | None:
        """
        Resolve the Redis password from the configured secret file path,
        falling back to the REDIS_PASSWORD environment variable, then None.
        """
        secret_path = Path(self.redis_password_file)
        if secret_path.exists():
            value = secret_path.read_text().strip()
            return value if value else None
        env_val = os.getenv("REDIS_PASSWORD")
        return env_val if env_val else None

    @cached_property
    def opensearch_password(self) -> str:
        """Resolve the OpenSearch password from the configured secret file."""
        secret_path = Path(self.opensearch_password_file)
        if secret_path.exists():
            return secret_path.read_text().strip()
        val = os.getenv("OPENSEARCH_PASSWORD")
        if val:
            return val
        raise RuntimeError("opensearch_password secret not found")

    @cached_property
    def jwt_secret(self) -> str:
        """Resolve the JWT signing secret from the configured secret file."""
        secret_path = Path(self.jwt_secret_file)
        if secret_path.exists():
            return secret_path.read_text().strip()
        val = os.getenv("JWT_SECRET")
        if val:
            return val
        raise RuntimeError("jwt_secret secret not found")

    @cached_property
    def db_url(self) -> str:
        """Build an asyncpg SQLAlchemy URL."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @cached_property
    def redis_url(self) -> str:
        """Build a redis:// URL from host, port, db, and password."""
        password = self.redis_password
        if password:
            return (
                f"redis://:{password}@{self.redis_host}:{self.redis_port}"
                f"/{self.redis_db}"
            )
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @cached_property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS_ORIGINS comma-separated string into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


# Module-level singleton — imported by all other modules
settings = Settings()
