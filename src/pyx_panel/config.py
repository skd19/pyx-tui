"""Configuration settings for pyx-panel."""
from __future__ import annotations

import os
import platform
import secrets
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment or defaults."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server settings
    panel_host: str = "0.0.0.0"
    panel_port: int = 8000
    panel_secret_token: str = ""
    session_secret_key: str = ""

    # Idle watchdog auto-shutdown (in minutes, 0 disables watchdog)
    idle_timeout_minutes: int = 15

    # Mock mode: automatically default to True on non-Linux OS (e.g. Windows/macOS)
    # or if explicitly set via environment
    mock_system: bool = platform.system() != "Linux"

    # Filesystem Paths
    nginx_sites_available: Path = Path("/etc/nginx/sites-available")
    nginx_sites_enabled: Path = Path("/etc/nginx/sites-enabled")
    nginx_conf_d: Path = Path("/etc/nginx/conf.d")
    nginx_main_config: Path = Path("/etc/nginx/nginx.conf")
    systemd_system_dir: Path = Path("/etc/systemd/system")
    apps_dir: Path = Path("/opt/apps")
    wireguard_dir: Path = Path("/etc/wireguard")
    wireguard_conf: Path = Path("/etc/wireguard/wg0.conf")

    # Mock data directory when mock_system is True
    mock_dir: Path = Path("./.pyx_mock")

    def get_token(self) -> str:
        """Returns the configured token or generates a secure 32-char token."""
        if not self.panel_secret_token:
            self.panel_secret_token = secrets.token_urlsafe(24)
        return self.panel_secret_token

    def get_session_secret(self) -> str:
        """Returns or generates session secret key."""
        if not self.session_secret_key:
            self.session_secret_key = secrets.token_hex(32)
        return self.session_secret_key


settings = Settings()
