"""System Driver protocol and interface."""
from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator, Protocol, runtime_checkable


@runtime_checkable
class SystemDriver(Protocol):
    """Protocol defining host system interactions (Nginx, systemd, files, certbot)."""

    async def run_command(self, cmd: list[str]) -> tuple[int, str, str]:
        """Execute a shell command. Returns (exit_code, stdout, stderr)."""
        ...

    async def test_nginx(self) -> tuple[bool, str]:
        """Validate Nginx configuration using 'nginx -t'. Returns (is_valid, output)."""
        ...

    async def reload_nginx(self) -> tuple[bool, str]:
        """Safely reloads Nginx. Returns (success, message)."""
        ...

    async def get_nginx_status(self) -> dict:
        """Returns dict with active status, version, and running state."""
        ...

    def write_file(self, path: Path | str, content: str) -> None:
        """Write content to file atomically."""
        ...

    def read_file(self, path: Path | str) -> str:
        """Read content from file."""
        ...

    def file_exists(self, path: Path | str) -> bool:
        """Check if file exists."""
        ...

    def delete_file(self, path: Path | str) -> None:
        """Delete file if it exists."""
        ...

    def list_dir(self, path: Path | str) -> list[str]:
        """List files in directory."""
        ...

    def create_symlink(self, src: Path | str, dst: Path | str) -> None:
        """Create symbolic link from src to dst."""
        ...

    def remove_symlink(self, path: Path | str) -> None:
        """Remove symbolic link."""
        ...

    def is_symlink(self, path: Path | str) -> bool:
        """Check if path is a symbolic link."""
        ...

    async def systemctl(self, action: str, unit: str) -> tuple[bool, str]:
        """Run systemctl action (start, stop, restart, reload, enable, disable) on unit."""
        ...

    async def daemon_reload(self) -> tuple[bool, str]:
        """Run systemctl daemon-reload."""
        ...

    async def get_service_status(self, unit: str) -> dict:
        """Returns status of a systemd unit (active_state, sub_state, enabled, pid, uptime)."""
        ...

    async def stream_journal_logs(self, unit: str, lines: int = 50) -> AsyncIterator[str]:
        """Yield real-time log lines from journalctl for a unit."""
        ...

    async def run_certbot(self, domain: str, email: str = "") -> tuple[bool, str]:
        """Run certbot for a domain."""
        ...

    async def list_certificates(self) -> list[dict]:
        """List issued SSL certificates."""
        ...

    async def get_ufw_status(self) -> dict:
        """Returns UFW firewall status, policies, and list of active rules."""
        ...

    async def ufw_allow(self, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        """Allow a port or service on UFW."""
        ...

    async def ufw_deny(self, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        """Deny a port or service on UFW."""
        ...

    async def ufw_delete_rule(self, rule_num: int) -> tuple[bool, str]:
        """Delete a UFW rule by numbered index."""
        ...

    async def ufw_set_enabled(self, enable: bool) -> tuple[bool, str]:
        """Enable or disable UFW firewall."""
        ...

    async def ufw_reset_default_policies(self) -> tuple[bool, str]:
        """Sets default policies: deny incoming, allow outgoing."""
        ...
