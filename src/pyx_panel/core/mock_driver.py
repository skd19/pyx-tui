"""Mock system driver for local development and cross-platform testing."""
from __future__ import annotations

import asyncio
import datetime
import os
import shutil
from pathlib import Path
from typing import AsyncIterator


class MockSystemDriver:
    """Mock implementation that manages files in a local directory without root."""

    def __init__(self, base_dir: Path | str = "./.pyx_mock") -> None:
        self.base_dir = Path(base_dir)
        self.sites_available = self.base_dir / "nginx" / "sites-available"
        self.sites_enabled = self.base_dir / "nginx" / "sites-enabled"
        self.systemd_dir = self.base_dir / "systemd" / "system"
        
        # Ensure directories exist
        self.sites_available.mkdir(parents=True, exist_ok=True)
        self.sites_enabled.mkdir(parents=True, exist_ok=True)
        self.systemd_dir.mkdir(parents=True, exist_ok=True)

        # Mock runtime state
        self.service_states: dict[str, dict] = {}
        self.mock_certs: list[dict] = []
        self.nginx_running = True

        # Pre-seed a sample Go service if empty
        self._seed_sample_data()

    def _seed_sample_data(self) -> None:
        sample_service_file = self.systemd_dir / "go-demo-app.service"
        if not sample_service_file.exists():
            sample_service_file.write_text(
                """[Unit]
Description=Demo Go API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/apps/go-demo
ExecStart=/opt/apps/go-demo/server
Restart=always
RestartSec=5s
Environment="PORT=8080"
Environment="GIN_MODE=release"

[Install]
WantedBy=multi-user.target
""",
                encoding="utf-8",
            )
            self.service_states["go-demo-app.service"] = {
                "active": True,
                "active_state": "active",
                "sub_state": "running",
                "unit_file_state": "enabled",
                "pid": "14285",
                "uptime": datetime.datetime.now().strftime("%a %Y-%m-%d %H:%M:%S UTC"),
                "description": "Demo Go API Server",
            }

        sample_site = self.sites_available / "go-demo-app.conf"
        if not sample_site.exists():
            sample_site.write_text(
                """server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
""",
                encoding="utf-8",
            )
            # Create enabled symlink or file
            self.create_symlink(sample_site, self.sites_enabled / "go-demo-app.conf")

    async def run_command(self, cmd: list[str]) -> tuple[int, str, str]:
        return 0, f"Mock executed: {' '.join(cmd)}", ""

    async def test_nginx(self) -> tuple[bool, str]:
        # Validate syntax of all files in sites-enabled (matching real nginx behavior)
        for conf_file in self.sites_enabled.iterdir():
            if conf_file.is_file() and conf_file.name.endswith(".conf"):
                content = conf_file.read_text(encoding="utf-8")
                # Simple check for balanced braces
                if content.count("{") != content.count("}"):
                    return False, f"nginx: [emerg] unexpected '}}' or '{{' in {conf_file.name}"
        return True, "nginx: configuration file test is successful"

    async def reload_nginx(self) -> tuple[bool, str]:
        is_valid, msg = await self.test_nginx()
        if not is_valid:
            return False, f"Nginx syntax error: {msg}"
        return True, "Nginx configuration reloaded successfully"

    async def get_nginx_status(self) -> dict:
        return {
            "active": self.nginx_running,
            "state": "active" if self.nginx_running else "inactive",
            "version": "nginx/1.24.0 (Mock Environment)",
        }

    def write_file(self, path: Path | str, content: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def read_file(self, path: Path | str) -> str:
        p = Path(path)
        if not p.exists():
            return ""
        return p.read_text(encoding="utf-8")

    def file_exists(self, path: Path | str) -> bool:
        return Path(path).exists()

    def delete_file(self, path: Path | str) -> None:
        p = Path(path)
        if p.exists() or p.is_symlink():
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()

    def list_dir(self, path: Path | str) -> list[str]:
        p = Path(path)
        if not p.exists() or not p.is_dir():
            return []
        return [f.name for f in p.iterdir()]

    def create_symlink(self, src: Path | str, dst: Path | str) -> None:
        s = Path(src)
        d = Path(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        if d.exists() or d.is_symlink():
            d.unlink()
        try:
            # On Windows without developer mode, os.symlink might require admin.
            # Fallback to copy or hard link if symlink fails in mock mode
            os.symlink(str(s), str(d))
        except (OSError, NotImplementedError):
            # Fallback: copy content
            d.write_text(s.read_text(encoding="utf-8"), encoding="utf-8")

    def remove_symlink(self, path: Path | str) -> None:
        p = Path(path)
        if p.exists() or p.is_symlink():
            p.unlink()

    def is_symlink(self, path: Path | str) -> bool:
        p = Path(path)
        return p.is_symlink() or (p.exists() and p.is_file())

    async def systemctl(self, action: str, unit: str) -> tuple[bool, str]:
        if unit not in self.service_states:
            self.service_states[unit] = {
                "active": False,
                "active_state": "inactive",
                "sub_state": "dead",
                "unit_file_state": "disabled",
                "pid": "0",
                "uptime": "",
                "description": unit,
            }
        
        st = self.service_states[unit]
        if action == "start":
            st["active"] = True
            st["active_state"] = "active"
            st["sub_state"] = "running"
            st["pid"] = "19401"
            st["uptime"] = datetime.datetime.now().strftime("%a %Y-%m-%d %H:%M:%S UTC")
        elif action == "stop":
            st["active"] = False
            st["active_state"] = "inactive"
            st["sub_state"] = "dead"
            st["pid"] = "0"
        elif action == "restart":
            st["active"] = True
            st["active_state"] = "active"
            st["sub_state"] = "running"
            st["pid"] = "20104"
            st["uptime"] = datetime.datetime.now().strftime("%a %Y-%m-%d %H:%M:%S UTC")
        elif action == "enable":
            st["unit_file_state"] = "enabled"
        elif action == "disable":
            st["unit_file_state"] = "disabled"

        return True, f"Mock: Service {unit} executed {action}"

    async def daemon_reload(self) -> tuple[bool, str]:
        return True, "Mock: systemctl daemon-reload completed"

    async def get_service_status(self, unit: str) -> dict:
        if unit not in self.service_states:
            unit_file = self.systemd_dir / unit
            exists = unit_file.exists()
            desc = unit
            if exists:
                content = unit_file.read_text(encoding="utf-8")
                for line in content.splitlines():
                    if line.startswith("Description="):
                        desc = line.split("=", 1)[1]
            self.service_states[unit] = {
                "name": unit,
                "active": False,
                "active_state": "inactive" if exists else "not-found",
                "sub_state": "dead",
                "unit_file_state": "enabled" if exists else "disabled",
                "pid": "0",
                "uptime": "",
                "description": desc,
            }
        
        res = dict(self.service_states[unit])
        res["name"] = unit
        return res

    async def stream_journal_logs(self, unit: str, lines: int = 50) -> AsyncIterator[str]:
        # Emit initial history
        now = datetime.datetime.now()
        for i in range(lines):
            t = (now - datetime.timedelta(seconds=(lines - i) * 5)).strftime("%Y-%m-%d %H:%M:%S")
            yield f"[{t}] INFO  [server] listening on :8080 (request #{i+1})"
        
        # Stream live logs
        counter = lines + 1
        while True:
            await asyncio.sleep(2.0)
            t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            yield f"[{t}] INFO  [server] HTTP GET /api/v1/health status=200 duration=1.2ms (req #{counter})"
            counter += 1

    async def run_certbot(self, domain: str, email: str = "") -> tuple[bool, str]:
        await asyncio.sleep(1.0)
        self.mock_certs.append({
            "name": domain,
            "domains": [domain],
            "expiry": (datetime.datetime.now() + datetime.timedelta(days=90)).strftime("%Y-%m-%d"),
        })
        return True, f"Successfully obtained certificate for {domain}\nCertificate is saved at: /etc/letsencrypt/live/{domain}/fullchain.pem"

    async def list_certificates(self) -> list[dict]:
        return self.mock_certs
