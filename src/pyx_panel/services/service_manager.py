"""Systemd service manager for Go servers and custom backend applications."""
from __future__ import annotations

import re
from pathlib import Path
from pydantic import BaseModel, Field
from pyx_panel.config import settings
from pyx_panel.core import get_driver


class ServiceForm(BaseModel):
    """Input form for creating or updating a systemd service."""
    name: str  # e.g. "go-server"
    description: str = "Backend Application"
    exec_start: str  # e.g. "/opt/apps/go-server/server"
    working_dir: str = ""  # e.g. "/opt/apps/go-server"
    user: str = "root"
    environment: str = ""  # Key=Value pairs, one per line
    restart: str = "always"
    restart_sec: str = "5s"
    autostart: bool = True  # Enable and start immediately


class ServiceDetail(BaseModel):
    """Metadata and runtime status of a managed systemd service."""
    name: str
    unit_name: str
    description: str = ""
    active: bool = False
    active_state: str = "inactive"
    sub_state: str = "dead"
    unit_file_state: str = "disabled"
    pid: str = "0"
    uptime: str = ""
    exec_start: str = ""
    working_dir: str = ""
    environment_vars: list[str] = Field(default_factory=list)
    content: str = ""


class ServiceManager:
    """Manages systemd unit creation, modification, and lifecycle operations."""

    def __init__(self) -> None:
        self.driver = get_driver()
        self.systemd_dir = settings.systemd_system_dir

    def _sanitize_name(self, name: str) -> str:
        """Sanitizes service name to ensure safe filename with .service suffix."""
        cleaned = re.sub(r"[^a-zA-Z0-9_\.-]", "_", name.strip())
        if not cleaned.endswith(".service"):
            cleaned += ".service"
        return cleaned

    def generate_unit_content(self, form: ServiceForm) -> str:
        """Generate standard systemd service unit file content."""
        workdir = form.working_dir.strip()
        if not workdir and form.exec_start.strip():
            # Default working dir to parent directory of the binary
            try:
                workdir = str(Path(form.exec_start.strip().split()[0]).parent)
            except Exception:
                workdir = "/opt"

        # Format environment lines
        env_lines = []
        for line in form.environment.splitlines():
            line_s = line.strip()
            if line_s and not line_s.startswith("#") and "=" in line_s:
                env_lines.append(f'Environment="{line_s}"')
        env_block = "\n".join(env_lines)
        if env_block:
            env_block = "\n" + env_block

        content = f"""[Unit]
Description={form.description.strip()}
After=network.target

[Service]
Type=simple
User={form.user.strip() or "root"}
WorkingDirectory={workdir}
ExecStart={form.exec_start.strip()}
Restart={form.restart}
RestartSec={form.restart_sec}{env_block}

[Install]
WantedBy=multi-user.target
"""
        return content

    async def list_services(self) -> list[ServiceDetail]:
        """Lists managed systemd services from the systemd directory."""
        filenames = self.driver.list_dir(self.systemd_dir)
        services: list[ServiceDetail] = []

        for fn in sorted(filenames):
            if not fn.endswith(".service"):
                continue
            # Avoid showing internal system units like pyx-panel itself or default OS units
            if fn.startswith("sys-") or fn.startswith("systemd-") or fn.startswith("dbus-"):
                continue

            unit_path = self.systemd_dir / fn
            content = self.driver.read_file(unit_path)
            
            # Extract basic details from file
            status = await self.driver.get_service_status(fn)

            exec_start = ""
            working_dir = ""
            desc = status.get("description") or fn
            env_vars: list[str] = []

            for line in content.splitlines():
                line_s = line.strip()
                if line_s.startswith("ExecStart="):
                    exec_start = line_s.split("=", 1)[1]
                elif line_s.startswith("WorkingDirectory="):
                    working_dir = line_s.split("=", 1)[1]
                elif line_s.startswith("Description=") and not desc:
                    desc = line_s.split("=", 1)[1]
                elif line_s.startswith("Environment="):
                    val = line_s.split("=", 1)[1].strip('"')
                    env_vars.append(val)

            name = fn[:-8] if fn.endswith(".service") else fn

            services.append(
                ServiceDetail(
                    name=name,
                    unit_name=fn,
                    description=desc,
                    active=status.get("active", False),
                    active_state=status.get("active_state", "inactive"),
                    sub_state=status.get("sub_state", "dead"),
                    unit_file_state=status.get("unit_file_state", "disabled"),
                    pid=status.get("pid", "0"),
                    uptime=status.get("uptime", ""),
                    exec_start=exec_start,
                    working_dir=working_dir,
                    environment_vars=env_vars,
                    content=content,
                )
            )

        return services

    async def get_service(self, name: str) -> ServiceDetail | None:
        """Fetch details for a single service."""
        unit_name = self._sanitize_name(name)
        unit_path = self.systemd_dir / unit_name

        if not self.driver.file_exists(unit_path):
            return None

        content = self.driver.read_file(unit_path)
        status = await self.driver.get_service_status(unit_name)

        exec_start = ""
        working_dir = ""
        desc = status.get("description") or unit_name
        env_vars: list[str] = []

        for line in content.splitlines():
            line_s = line.strip()
            if line_s.startswith("ExecStart="):
                exec_start = line_s.split("=", 1)[1]
            elif line_s.startswith("WorkingDirectory="):
                working_dir = line_s.split("=", 1)[1]
            elif line_s.startswith("Description=") and not desc:
                desc = line_s.split("=", 1)[1]
            elif line_s.startswith("Environment="):
                val = line_s.split("=", 1)[1].strip('"')
                env_vars.append(val)

        short_name = unit_name[:-8] if unit_name.endswith(".service") else unit_name
        return ServiceDetail(
            name=short_name,
            unit_name=unit_name,
            description=desc,
            active=status.get("active", False),
            active_state=status.get("active_state", "inactive"),
            sub_state=status.get("sub_state", "dead"),
            unit_file_state=status.get("unit_file_state", "disabled"),
            pid=status.get("pid", "0"),
            uptime=status.get("uptime", ""),
            exec_start=exec_start,
            working_dir=working_dir,
            environment_vars=env_vars,
            content=content,
        )

    async def create_or_update_service(self, form: ServiceForm) -> tuple[bool, str]:
        """Creates or updates a systemd service unit file."""
        unit_name = self._sanitize_name(form.name)
        unit_path = self.systemd_dir / unit_name

        content = self.generate_unit_content(form)
        self.driver.write_file(unit_path, content)

        # Reload daemon to pick up changes
        await self.driver.daemon_reload()

        if form.autostart:
            await self.driver.systemctl("enable", unit_name)
            await self.driver.systemctl("restart", unit_name)

        return True, f"Service {unit_name} configured successfully"

    async def save_raw_unit(self, name: str, content: str) -> tuple[bool, str]:
        """Save raw unit content directly."""
        unit_name = self._sanitize_name(name)
        unit_path = self.systemd_dir / unit_name

        self.driver.write_file(unit_path, content)
        await self.driver.daemon_reload()
        return True, f"Service {unit_name} saved"

    async def start(self, name: str) -> tuple[bool, str]:
        return await self.driver.systemctl("start", self._sanitize_name(name))

    async def stop(self, name: str) -> tuple[bool, str]:
        return await self.driver.systemctl("stop", self._sanitize_name(name))

    async def restart(self, name: str) -> tuple[bool, str]:
        return await self.driver.systemctl("restart", self._sanitize_name(name))

    async def enable(self, name: str) -> tuple[bool, str]:
        return await self.driver.systemctl("enable", self._sanitize_name(name))

    async def disable(self, name: str) -> tuple[bool, str]:
        return await self.driver.systemctl("disable", self._sanitize_name(name))

    async def delete(self, name: str) -> tuple[bool, str]:
        unit_name = self._sanitize_name(name)
        unit_path = self.systemd_dir / unit_name

        # Stop and disable first
        await self.driver.systemctl("stop", unit_name)
        await self.driver.systemctl("disable", unit_name)

        # Remove unit file
        self.driver.delete_file(unit_path)
        await self.driver.daemon_reload()

        return True, f"Service {unit_name} deleted"


service_manager = ServiceManager()
