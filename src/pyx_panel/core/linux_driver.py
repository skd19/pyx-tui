"""Linux host system driver implementation."""
from __future__ import annotations

import asyncio
import os
import re
import shutil
from pathlib import Path
from typing import AsyncIterator


class LinuxSystemDriver:
    """Interacts directly with Linux host systemd, Nginx, and Certbot."""

    async def run_command(self, cmd: list[str]) -> tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await proc.communicate()
            return (
                proc.returncode if proc.returncode is not None else 1,
                stdout_bytes.decode("utf-8", errors="replace"),
                stderr_bytes.decode("utf-8", errors="replace"),
            )
        except Exception as e:
            return 1, "", str(e)

    async def test_nginx(self) -> tuple[bool, str]:
        code, stdout, stderr = await self.run_command(["nginx", "-t"])
        output = (stdout + "\n" + stderr).strip()
        return code == 0, output

    async def reload_nginx(self) -> tuple[bool, str]:
        # Validate first
        is_valid, test_out = await self.test_nginx()
        if not is_valid:
            return False, f"Nginx syntax error: {test_out}"
        code, stdout, stderr = await self.run_command(["systemctl", "reload", "nginx"])
        if code != 0:
            return False, (stderr or stdout).strip()
        return True, "Nginx successfully reloaded"

    async def get_nginx_status(self) -> dict:
        code, stdout, _ = await self.run_command(["systemctl", "is-active", "nginx"])
        active_state = stdout.strip() if code == 0 else "inactive"
        code_ver, _, stderr_ver = await self.run_command(["nginx", "-v"])
        version = stderr_ver.strip() if stderr_ver else "nginx unknown"
        return {
            "active": active_state == "active",
            "state": active_state,
            "version": version,
        }

    def write_file(self, path: Path | str, content: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write
        temp_p = p.with_suffix(p.suffix + ".tmp")
        temp_p.write_text(content, encoding="utf-8")
        temp_p.replace(p)

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
                os.rmdir(p)
            else:
                p.unlink()

    def copy_file(self, src: Path | str, dst: Path | str) -> None:
        s = Path(src)
        d = Path(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        if d.is_symlink() or d.exists():
            d.unlink()
        shutil.copy2(str(s), str(d))

    def list_dir(self, path: Path | str) -> list[str]:
        p = Path(path)
        if not p.exists() or not p.is_dir():
            return []
        return [f.name for f in p.iterdir()]

    def create_symlink(self, src: Path | str, dst: Path | str) -> None:
        s = Path(src)
        d = Path(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        if d.is_symlink() or d.exists():
            d.unlink()
        os.symlink(str(s), str(d))

    def remove_symlink(self, path: Path | str) -> None:
        p = Path(path)
        if p.is_symlink() or p.exists():
            p.unlink()

    def is_symlink(self, path: Path | str) -> bool:
        return Path(path).is_symlink()

    async def systemctl(self, action: str, unit: str) -> tuple[bool, str]:
        valid_actions = {"start", "stop", "restart", "reload", "enable", "disable"}
        if action not in valid_actions:
            return False, f"Invalid systemctl action: {action}"
        code, stdout, stderr = await self.run_command(["systemctl", action, unit])
        if code != 0:
            return False, (stderr or stdout).strip()
        return True, f"Successfully executed '{action}' on {unit}"

    async def daemon_reload(self) -> tuple[bool, str]:
        code, stdout, stderr = await self.run_command(["systemctl", "daemon-reload"])
        if code != 0:
            return False, (stderr or stdout).strip()
        return True, "systemctl daemon-reload succeeded"

    async def get_service_status(self, unit: str) -> dict:
        code, stdout, _ = await self.run_command(
            [
                "systemctl",
                "show",
                unit,
                "--property=ActiveState,SubState,UnitFileState,MainPID,ActiveEnterTimestamp,Description",
            ]
        )
        props: dict[str, str] = {}
        if code == 0:
            for line in stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()

        active = props.get("ActiveState") == "active"
        return {
            "name": unit,
            "active": active,
            "active_state": props.get("ActiveState", "unknown"),
            "sub_state": props.get("SubState", "unknown"),
            "unit_file_state": props.get("UnitFileState", "unknown"),
            "pid": props.get("MainPID", "0"),
            "uptime": props.get("ActiveEnterTimestamp", ""),
            "description": props.get("Description", ""),
        }

    async def stream_journal_logs(self, unit: str, lines: int = 50) -> AsyncIterator[str]:
        cmd = [
            "journalctl",
            "-u",
            unit,
            f"-n{lines}",
            "-f",
            "--no-tail",
            "--output=cat",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            while True:
                if proc.stdout is None:
                    break
                line = await proc.stdout.readline()
                if not line:
                    break
                yield line.decode("utf-8", errors="replace").rstrip("\r\n")
        finally:
            try:
                proc.terminate()
                await proc.wait()
            except Exception:
                pass

    async def run_certbot(self, domain: str, email: str = "") -> tuple[bool, str]:
        cmd = [
            "certbot",
            "--nginx",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "--redirect",
        ]
        if email.strip():
            cmd.extend(["-m", email.strip()])
        else:
            cmd.append("--register-unsafely-without-email")

        code, stdout, stderr = await self.run_command(cmd)
        output = (stdout + "\n" + stderr).strip()
        return code == 0, output

    async def list_certificates(self) -> list[dict]:
        code, stdout, _ = await self.run_command(["certbot", "certificates"])
        if code != 0 or not stdout:
            return []
        
        # Parse certbot output
        certs = []
        blocks = stdout.split("Certificate Name: ")
        for block in blocks[1:]:
            lines = block.splitlines()
            name = lines[0].strip()
            domains = []
            expiry = ""
            for line in lines:
                if "Domains:" in line:
                    domains = [d.strip() for d in line.split("Domains:")[1].split()]
                elif "Expiry Date:" in line:
                    expiry = line.split("Expiry Date:")[1].strip()
            certs.append({
                "name": name,
                "domains": domains,
                "expiry": expiry,
            })
        return certs

    async def get_ufw_status(self) -> dict:
        code, stdout, _ = await self.run_command(["ufw", "status", "verbose"])
        is_active = "Status: active" in stdout

        default_incoming = "deny"
        default_outgoing = "allow"
        m_def = re.search(r"Default:\s*([a-zA-Z]+)\s*\(incoming\),\s*([a-zA-Z]+)\s*\(outgoing\)", stdout)
        if m_def:
            default_incoming = m_def.group(1).lower()
            default_outgoing = m_def.group(2).lower()

        rules = []
        if is_active:
            code_num, stdout_num, _ = await self.run_command(["ufw", "status", "numbered"])
            if code_num == 0:
                for line in stdout_num.splitlines():
                    line_s = line.strip()
                    m = re.match(r"^\[\s*(\d+)\]\s+(.*?)\s{2,}(ALLOW IN|DENY IN|REJECT IN|ALLOW|DENY|REJECT)\s+(.*?)(?:\s+#\s*(.*))?$", line_s)
                    if m:
                        index = int(m.group(1))
                        to_target = m.group(2).strip()
                        action = m.group(3).strip()
                        from_src = m.group(4).strip()
                        comment = (m.group(5) or "").strip()

                        is_v6 = "(v6)" in to_target or "(v6)" in from_src
                        proto = "any"
                        port_part = to_target.replace("(v6)", "").strip()
                        if "/tcp" in port_part:
                            proto = "tcp"
                            port_part = port_part.replace("/tcp", "").strip()
                        elif "/udp" in port_part:
                            proto = "udp"
                            port_part = port_part.replace("/udp", "").strip()

                        rules.append({
                            "index": index,
                            "port": port_part,
                            "proto": proto,
                            "to": to_target,
                            "action": action,
                            "from": from_src,
                            "comment": comment,
                            "is_v6": is_v6,
                        })

        return {
            "active": is_active,
            "default_incoming": default_incoming,
            "default_outgoing": default_outgoing,
            "rules": rules,
        }

    async def ufw_allow(self, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        target = f"{port}/{proto}" if proto in ("tcp", "udp") else port
        cmd = ["ufw", "allow", target]
        if comment.strip():
            cmd.extend(["comment", comment.strip()])
        code, stdout, stderr = await self.run_command(cmd)
        msg = (stdout + "\n" + stderr).strip()
        return code == 0, msg

    async def ufw_allow_from(self, src_ip: str, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        cmd = ["ufw", "allow", "from", src_ip, "to", "any", "port", str(port)]
        if proto in ("tcp", "udp"):
            cmd.extend(["proto", proto])
        if comment.strip():
            cmd.extend(["comment", comment.strip()])
        code, stdout, stderr = await self.run_command(cmd)
        msg = (stdout + "\n" + stderr).strip()
        return code == 0, msg

    async def ufw_deny(self, port: str, proto: str = "tcp", comment: str = "") -> tuple[bool, str]:
        target = f"{port}/{proto}" if proto in ("tcp", "udp") else port
        cmd = ["ufw", "deny", target]
        if comment.strip():
            cmd.extend(["comment", comment.strip()])
        code, stdout, stderr = await self.run_command(cmd)
        msg = (stdout + "\n" + stderr).strip()
        return code == 0, msg

    async def ufw_delete_rule(self, rule_num: int) -> tuple[bool, str]:
        code, stdout, stderr = await self.run_command(["ufw", "--force", "delete", str(rule_num)])
        msg = (stdout + "\n" + stderr).strip()
        return code == 0, msg

    async def ufw_delete_rule_by_spec(self, rule_spec: list[str]) -> tuple[bool, str]:
        cmd = ["ufw", "--force", "delete"] + rule_spec
        code, stdout, stderr = await self.run_command(cmd)
        msg = (stdout + "\n" + stderr).strip()
        return code == 0, msg

    async def ufw_set_enabled(self, enable: bool) -> tuple[bool, str]:
        cmd = ["ufw", "--force", "enable"] if enable else ["ufw", "disable"]
        code, stdout, stderr = await self.run_command(cmd)
        msg = (stdout + "\n" + stderr).strip()
        return code == 0, msg

    async def ufw_reset_default_policies(self) -> tuple[bool, str]:
        c1, o1, e1 = await self.run_command(["ufw", "default", "deny", "incoming"])
        c2, o2, e2 = await self.run_command(["ufw", "default", "allow", "outgoing"])
        success = (c1 == 0 and c2 == 0)
        return success, "Default policies configured: deny incoming, allow outgoing"

    async def check_package_status(self, package_name: str, binary_cmd: str | None = None) -> dict:
        cmd_name = binary_cmd or package_name
        is_installed = False
        version_str = ""
        service_active = False

        # 1. Check via dpkg-query for apt packages
        code, stdout, _ = await self.run_command(["dpkg-query", "-W", "-f=${Status}\t${Version}\n", package_name])
        if code == 0 and "install ok installed" in stdout:
            is_installed = True
            parts = stdout.strip().split("\t")
            if len(parts) > 1:
                version_str = parts[1].strip()

        # 2. Check via which/binary if not detected via dpkg (e.g. uv or custom installs)
        if not is_installed:
            w_code, w_out, _ = await self.run_command(["which", cmd_name])
            if w_code == 0 and w_out.strip():
                is_installed = True

        # Extract cleaner version if missing or binary specific
        if is_installed and not version_str:
            v_code, v_out, v_err = await self.run_command([cmd_name, "--version"])
            if v_code == 0 and (v_out or v_err):
                version_str = (v_out or v_err).strip().splitlines()[0]

        # 3. Check service state if it's a daemon
        if package_name in ("nginx", "ufw"):
            s_code, s_out, _ = await self.run_command(["systemctl", "is-active", package_name])
            service_active = (s_out.strip() == "active")

        return {
            "name": package_name,
            "installed": is_installed,
            "version": version_str,
            "service_active": service_active,
        }

    async def install_system_packages(self, packages: list[str]) -> AsyncIterator[str]:
        if not packages:
            yield "No packages specified for installation."
            return

        apt_pkgs = [p for p in packages if p != "uv"]
        install_uv = "uv" in packages

        if apt_pkgs:
            yield f"[1/2] Updating package repositories: apt-get update..."
            cmd_up = ["apt-get", "update", "-y"]
            proc_up = await asyncio.create_subprocess_exec(
                *cmd_up,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            if proc_up.stdout:
                while True:
                    line = await proc_up.stdout.readline()
                    if not line:
                        break
                    yield line.decode("utf-8", errors="replace").rstrip("\r\n")
            await proc_up.wait()

            yield f"[2/2] Installing system packages: {' '.join(apt_pkgs)}..."
            cmd_in = ["apt-get", "install", "-y", *apt_pkgs]
            proc_in = await asyncio.create_subprocess_exec(
                *cmd_in,
                env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            if proc_in.stdout:
                while True:
                    line = await proc_in.stdout.readline()
                    if not line:
                        break
                    yield line.decode("utf-8", errors="replace").rstrip("\r\n")
            await proc_in.wait()

        if install_uv:
            yield "[uv] Installing uv package manager via astral.sh..."
            proc_uv = await asyncio.create_subprocess_shell(
                "curl -LsSf https://astral.sh/uv/install.sh | sh",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            if proc_uv.stdout:
                while True:
                    line = await proc_uv.stdout.readline()
                    if not line:
                        break
                    yield line.decode("utf-8", errors="replace").rstrip("\r\n")
            await proc_uv.wait()

        yield "[pyx-panel] Package installation process finished."
