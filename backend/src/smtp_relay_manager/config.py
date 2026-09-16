"""Environment-backed application settings."""

from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configure both entrypoints from the same environment."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "mysql+asyncmy://relay:relay@mysql/relay"
    encryption_key: str = ""
    public_base_url: str = "https://localhost"
    session_cookie_name: str = "__Host-relay-session"
    session_hours: int = Field(default=12, ge=1, le=168)
    invitation_hours: int = Field(default=24, ge=1, le=168)
    trusted_proxy_cidrs: str = ""
    smtp_hostname: str = "localhost"
    smtp_cert_dir: Path = Path("/app/cert")
    smtp_host: str = "0.0.0.0"
    smtp_tls_port: int = Field(default=8465, ge=1, le=65535)
    smtp_starttls_port: int = Field(default=8587, ge=1, le=65535)
    smtp_max_message_bytes: int = Field(default=25 * 1024 * 1024, ge=1024)
    smtp_max_recipients: int = Field(default=100, ge=1, le=1000)
    smtp_max_connections: int = Field(default=32, ge=1, le=1024)
    smtp_max_data_connections: int = Field(default=4, ge=1, le=64)
    smtp_idle_timeout: float = Field(default=60, gt=0)
    smtp_connect_timeout: float = Field(default=15, gt=0)
    smtp_command_timeout: float = Field(default=30, gt=0)
    smtp_transaction_timeout: float = Field(default=120, gt=0)
    smtp_cert_reload_seconds: float = Field(default=30, gt=0)
    log_retention_days: int = 30

    def validate_secrets(self) -> None:
        """Validate required encryption material before serving requests.

        Raises:
            ValueError: If the configured key is absent or malformed.
        """
        if not self.encryption_key:
            raise ValueError("ENCRYPTION_KEY is required")
        Fernet(self.encryption_key.encode("ascii"))


@lru_cache
def get_settings() -> Settings:
    """Load and cache process settings.

    Returns:
        Validated settings read from the environment and optional dotenv file.
    """
    return Settings()
