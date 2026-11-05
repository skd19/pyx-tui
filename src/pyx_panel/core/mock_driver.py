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
        self.conf_d = self.base_dir / "nginx" / "conf.d"
        self.systemd_dir = self.base_dir / "systemd" / "system"
        
        # Ensure directories exist
        self.sites_available.mkdir(parents=True, exist_ok=True)
        self.sites_enabled.mkdir(parents=True, exist_ok=True)
        self.conf_d.mkdir(parents=True, exist_ok=True)
        self.systemd_dir.mkdir(parents=True, exist_ok=True)

        # Mock runtime state
        self.service_states: dict[str, dict] = {}
        self.mock_certs: list[dict] = []
        self.nginx_running = True
        self.ufw_active = True
        self.ufw_default_incoming = "deny"
        self.ufw_default_outgoing = "allow"
        self.ufw_rules: list[dict] = [
            {"index": 1, "port": "22", "proto": "tcp", "to": "22/tcp", "action": "ALLOW IN", "from": "Anywhere", "comment": "SSH", "is_v6": False},
            {"index": 2, "port": "80", "proto": "tcp", "to": "80/tcp", "action": "ALLOW IN", "from": "Anywhere", "comment": "HTTP", "is_v6": False},
            {"index": 3, "port": "443", "proto": "tcp", "to": "443/tcp", "action": "ALLOW IN", "from": "Anywhere", "comment": "HTTPS", "is_v6": False},
        ]
        self.mock_installed_packages: set[str] = {
            "nginx",
            "ufw",
            "certbot",
            "python3-certbot-nginx",
            "curl",
            "git",
            "uv",
            "systemd",
        }
        self.mock_package_versions: dict[str, str] = {
            "nginx": "1.24.0 (Ubuntu)",
            "ufw": "0.36.2",
            "certbot": "2.9.0",
            "python3-certbot-nginx": "2.9.0-1",
            "curl": "8.5.0",
            "git": "2.43.0",
            "uv": "0.4.29",
            "systemd": "255.4-1ubuntu8",
        }
        self.mock_listening_ports: list[dict] = [
            {"proto": "tcp", "host": "0.0.0.0", "port": "22", "is_loopback": False, "is_public": True, "process": "sshd"},
            {"proto": "tcp", "host": "0.0.0.0", "port": "80", "is_loopback": False, "is_public": True, "process": "nginx"},
            {"proto": "tcp", "host": "0.0.0.0", "port": "443", "is_loopback": False, "is_public": True, "process": "nginx"},
            {"proto": "tcp", "host": "127.0.0.1", "port": "8080", "is_loopback": True, "is_public": False, "process": "go-server"},
            {"proto": "tcp", "host": "0.0.0.0", "port": "8000", "is_loopback": False, "is_public": True, "process": "pyx-panel"},
        ]
        self.mock_ssh_config: dict = {
            "port": 22,
            "password_authentication": True,
            "permit_root_login": "prohibit-password",
        }
        self.mock_has_authorized_keys: bool = True
        self.mock_sysctl: dict[str, str] = {
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.all.accept_source_route": "0",
        }

    async def run_command(self, cmd: list[str]) -> tuple[int, str, str]:
        return 0, f"Mock executed: {' '.join(cmd)}", ""

    async def test_nginx(self) -> tuple[bool, str]:
        # Validate syntax of all files in sites-enabled (matching real nginx behavior)
        default_servers = []
        for conf_file in self.sites_enabled.iterdir():
            if conf_file.is_file():
                content = conf_file.read_text(encoding="utf-8")
                # Simple check for balanced braces
                if content.count("{") != content.count("}"):
                    return False, f"nginx: [emerg] unexpected '}}' or '{{' in {conf_file.name}"
                # Check for duplicate default_server on port 80
                if "default_server" in content and ("listen 80" in content or "listen [::]:80" in content):
                    default_servers.append(conf_file.name)
        if len(default_servers) > 1:
            return False, f"nginx: [emerg] 20428#20428: a duplicate default server for 0.0.0.0:80 in {default_servers[-1]}"
        for conf_file in self.conf_d.iterdir():
            if conf_file.is_file():
                content = conf_file.read_text(encoding="utf-8")
                if content.count("{") != content.count("}"):
                    return False, f"nginx: [emerg] unexpected '}}' or '{{' in conf.d/{conf_file.name}"
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

    def copy_file(self, src: Path | str, dst: Path | str) -> None:
        s = Path(src)
        d = Path(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        if d.exists() or d.is_symlink():
            d.unlink()
        d.write_text(s.read_text(encoding="utf-8"), encoding="utf-8")

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

    async def get_ufw_status(self) -> dict:
        return {
            "active": self.ufw_active,
            "default_incoming": self.ufw_default_incoming,
            "default_outgoing": self.ufw_default_outgoing,
            "rules": [dict(r) for r in self.ufw_rules] if self.ufw_active else [],
        }

    async def ufw_allow(self, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        target = f"{port}/{proto}" if proto in ("tcp", "udp") else port
        idx = len(self.ufw_rules) + 1
        self.ufw_rules.append({
            "index": idx,
            "port": port,
            "proto": proto,
            "to": target,
            "action": "ALLOW IN",
            "from": "Anywhere",
            "comment": comment.strip(),
            "is_v6": False,
        })
        return True, f"Rule added: allow {target}"

    async def ufw_allow_from(self, src_ip: str, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        target = f"{port}/{proto}" if proto in ("tcp", "udp") else port
        idx = len(self.ufw_rules) + 1
        is_v6 = ":" in src_ip
        self.ufw_rules.append({
            "index": idx,
            "port": port,
            "proto": proto,
            "to": f"{target} (v6)" if is_v6 else target,
            "action": "ALLOW IN",
            "from": f"{src_ip} (v6)" if is_v6 else src_ip,
            "comment": comment.strip(),
            "is_v6": is_v6,
        })
        return True, f"Rule added: allow from {src_ip} to {target}"

    async def ufw_deny(self, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        target = f"{port}/{proto}" if proto in ("tcp", "udp") else port
        idx = len(self.ufw_rules) + 1
        self.ufw_rules.append({
            "index": idx,
            "port": port,
            "proto": proto,
            "to": target,
            "action": "DENY IN",
            "from": "Anywhere",
            "comment": comment.strip(),
            "is_v6": False,
        })
        return True, f"Rule added: deny {target}"

    async def ufw_delete_rule(self, rule_num: int) -> tuple[bool, str]:
        found = False
        new_rules = []
        for r in self.ufw_rules:
            if r["index"] == rule_num:
                found = True
                continue
            new_rules.append(r)
        if not found:
            return False, f"Rule #{rule_num} not found"
        # Re-index
        for i, r in enumerate(new_rules, start=1):
            r["index"] = i
        self.ufw_rules = new_rules
        return True, f"Rule #{rule_num} deleted"

    async def ufw_delete_rule_by_spec(self, rule_spec: list[str]) -> tuple[bool, str]:
        # Simple mock deletion based on port matching in spec
        spec_str = " ".join(rule_spec)
        new_rules = []
        deleted = False
        for r in self.ufw_rules:
            # Check if port matches e.g. "80/tcp" or "80"
            if any(part in spec_str for part in [r["port"], r["to"]]) and (r["from"] == "Anywhere" or "Anywhere" in spec_str):
                deleted = True
                continue
            new_rules.append(r)
        for i, r in enumerate(new_rules, start=1):
            r["index"] = i
        self.ufw_rules = new_rules
        return True, f"Rule matching spec deleted"

    async def ufw_set_enabled(self, enable: bool) -> tuple[bool, str]:
        self.ufw_active = enable
        state = "enabled" if enable else "disabled"
        return True, f"Firewall is now {state}"

    async def ufw_reset_default_policies(self) -> tuple[bool, str]:
        self.ufw_default_incoming = "deny"
        self.ufw_default_outgoing = "allow"
        return True, "Default policies reset to deny incoming, allow outgoing"

    async def check_package_status(self, package_name: str, binary_cmd: str | None = None) -> dict:
        installed = package_name in self.mock_installed_packages
        version = self.mock_package_versions.get(package_name, "1.0.0") if installed else ""
        service_active = False
        if package_name == "nginx":
            service_active = self.nginx_running
        elif package_name == "ufw":
            service_active = self.ufw_active

        return {
            "name": package_name,
            "installed": installed,
            "version": version,
            "service_active": service_active,
        }

    async def install_system_packages(self, packages: list[str]) -> AsyncIterator[str]:
        yield f"[pyx-mock] Starting installation of {len(packages)} packages: {', '.join(packages)}"
        await asyncio.sleep(0.01)
        for pkg in packages:
            yield f"[pyx-mock] Fetching & configuring {pkg}..."
            self.mock_installed_packages.add(pkg)
            if pkg not in self.mock_package_versions:
                self.mock_package_versions[pkg] = "1.0.0-mock"
            await asyncio.sleep(0.01)
            yield f"[pyx-mock] \u2705 {pkg} installed successfully."
        yield "[pyx-mock] All requested packages are installed and configured."

    async def get_listening_ports(self) -> list[dict]:
        return list(self.mock_listening_ports)

    async def read_ssh_config(self) -> dict:
        return dict(self.mock_ssh_config)

    async def has_ssh_authorized_keys(self) -> bool:
        return self.mock_has_authorized_keys

    async def write_ssh_hardening(self, disable_password_auth: bool, disable_root_login: bool) -> tuple[bool, str]:
        self.mock_ssh_config["password_authentication"] = not disable_password_auth
        self.mock_ssh_config["permit_root_login"] = "prohibit-password" if disable_root_login else "yes"
        return True, "Mock SSH configuration hardened successfully"

    async def apply_sysctl_settings(self, settings_dict: dict[str, str]) -> tuple[bool, str]:
        self.mock_sysctl.update(settings_dict)
        return True, f"Mock kernel network security parameters applied ({len(settings_dict)} settings)"

    async def read_sysctl_setting(self, key: str) -> str:
        return self.mock_sysctl.get(key, "1")
