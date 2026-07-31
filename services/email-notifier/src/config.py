"""
Configuration for the email-notifier service.

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
    Changing an env var at container start is sufficient to reconfigure.
    """

    # Redis connection
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password_file: str = "/run/secrets/redis_password"

    # SMTP configuration
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password_file: str = "/run/secrets/smtp_password"
    smtp_from: str = "siem@localhost"
    smtp_starttls: bool = True

    # Alert recipients — comma-separated list of email addresses
    alert_recipients: str = ""

    # Observability
    log_level: str = "INFO"
    metrics_port: int = 8084

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    # ------------------------------------------------------------------
    # Computed helpers (not loaded from env)
    # ------------------------------------------------------------------

    @cached_property
    def redis_password(self) -> str | None:
        """
        Resolve the Redis password from the configured secret file path,
        falling back to the REDIS_PASSWORD environment variable, then None.

        Returns None if the password is genuinely absent (no-auth Redis).
        """
        secret_path = Path(self.redis_password_file)
        if secret_path.exists():
            value = secret_path.read_text().strip()
            return value if value else None
        env_val = os.getenv("REDIS_PASSWORD")
        return env_val if env_val else None

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
    def smtp_password(self) -> str | None:
        """
        Resolve the SMTP password from the configured secret file, falling
        back to the SMTP_PASSWORD environment variable, then None.
        """
        secret_path = Path(self.smtp_password_file)
        if secret_path.exists():
            value = secret_path.read_text().strip()
            return value if value else None
        env_val = os.getenv("SMTP_PASSWORD")
        return env_val if env_val else None

    @cached_property
    def recipients_list(self) -> list[str]:
        """Parse ALERT_RECIPIENTS comma-separated string into a list."""
        return [r.strip() for r in self.alert_recipients.split(",") if r.strip()]
