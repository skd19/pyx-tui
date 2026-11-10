"""Package and prerequisite application management service."""
from __future__ import annotations

from typing import AsyncIterator
from pydantic import BaseModel
from pyx_panel.core import get_driver


class PackageInfo(BaseModel):
    """Metadata and runtime status for a system prerequisite or package."""
    id: str
    name: str
    category: str
    description: str
    package_name: str
    binary_cmd: str
    installed: bool = False
    version: str = ""
    service_active: bool = False
    required: bool = True


DEFAULT_PACKAGE_CATALOG: list[dict] = [
    {
        "id": "nginx",
        "name": "Nginx Web Server",
        "category": "Core Web",
        "description": "High-performance reverse proxy, HTTP server, and static file server.",
        "package_name": "nginx",
        "binary_cmd": "nginx",
        "required": True,
    },
    {
        "id": "ufw",
        "name": "UFW Firewall",
        "category": "Security",
        "description": "Programmatic firewall management, port isolation, and Cloudflare shielding.",
        "package_name": "ufw",
        "binary_cmd": "ufw",
        "required": True,
    },
    {
        "id": "certbot",
        "name": "Certbot (Let's Encrypt)",
        "category": "SSL / TLS",
        "description": "Automated SSL/TLS certificate issuance, renewal, and HTTPS redirection.",
        "package_name": "certbot",
        "binary_cmd": "certbot",
        "required": True,
    },
    {
        "id": "python3-certbot-nginx",
        "name": "Certbot Nginx Plugin",
        "category": "SSL / TLS",
        "description": "Enables Certbot to automatically configure Nginx virtual hosts for SSL certificates.",
        "package_name": "python3-certbot-nginx",
        "binary_cmd": "certbot",
        "required": True,
    },
    {
        "id": "curl",
        "name": "cURL HTTP Client",
        "category": "Utilities",
        "description": "Command line tool for network diagnostic checks and downloading IP CIDRs.",
        "package_name": "curl",
        "binary_cmd": "curl",
        "required": True,
    },
    {
        "id": "git",
        "name": "Git Version Control",
        "category": "Utilities",
        "description": "Source code control for cloning, pulling updates, and managing panel code.",
        "package_name": "git",
        "binary_cmd": "git",
        "required": False,
    },
    {
        "id": "uv",
        "name": "uv Python Manager",
        "category": "Runtimes",
        "description": "Extremely fast Python package installer and resolver powering pyx-panel.",
        "package_name": "uv",
        "binary_cmd": "uv",
        "required": True,
    },
    {
        "id": "systemd",
        "name": "Systemd & Journalctl",
        "category": "Supervisor",
        "description": "Linux init supervisor for backend Go apps and real-time live log streaming.",
        "package_name": "systemd",
        "binary_cmd": "systemctl",
        "required": True,
    },
    {
        "id": "php-fpm",
        "name": "PHP FastCGI (PHP-FPM)",
        "category": "WordPress & PHP",
        "description": "High-performance PHP FastCGI manager and extensions (php-mysql, php-curl, php-gd, php-mbstring, php-xml, php-zip) required for WordPress.",
        "package_name": "php-fpm",
        "binary_cmd": "php",
        "required": False,
    },
    {
        "id": "mariadb-server",
        "name": "MariaDB Database Server",
        "category": "Database",
        "description": "Fast, robust MySQL-compatible relational database server for WordPress content and metadata.",
        "package_name": "mariadb-server",
        "binary_cmd": "mariadb",
        "required": False,
    },
    {
        "id": "wp-cli",
        "name": "WP-CLI (WordPress CLI)",
        "category": "WordPress & PHP",
        "description": "Command line interface for managing WordPress installations, updating plugins, and database maintenance.",
        "package_name": "wp-cli",
        "binary_cmd": "wp",
        "required": False,
    },
    {
        "id": "wireguard",
        "name": "WireGuard Kernel Module",
        "category": "VPN & Networking",
        "description": "Extremely fast, modern, and cryptographically advanced VPN protocol built directly into Linux.",
        "package_name": "wireguard",
        "binary_cmd": "wg",
        "required": False,
    },
    {
        "id": "wireguard-tools",
        "name": "WireGuard CLI Tools (wg-quick)",
        "category": "VPN & Networking",
        "description": "Configuration utilities, curve25519 key generators, and interface orchestration scripts for WireGuard.",
        "package_name": "wireguard-tools",
        "binary_cmd": "wg-quick",
        "required": False,
    },
]


class PackageManager:
    """Inspects, monitors, and installs system packages and dependencies."""

    def __init__(self) -> None:
        self.driver = get_driver()

    async def get_packages(self) -> list[PackageInfo]:
        """Returns the full catalog of prerequisite packages with their live installation states."""
        results: list[PackageInfo] = []
        for defn in DEFAULT_PACKAGE_CATALOG:
            status = await self.driver.check_package_status(
                package_name=defn["package_name"],
                binary_cmd=defn["binary_cmd"],
            )
            results.append(
                PackageInfo(
                    id=defn["id"],
                    name=defn["name"],
                    category=defn["category"],
                    description=defn["description"],
                    package_name=defn["package_name"],
                    binary_cmd=defn["binary_cmd"],
                    installed=status.get("installed", False),
                    version=status.get("version", ""),
                    service_active=status.get("service_active", False),
                    required=defn["required"],
                )
            )
        return results

    async def get_missing_packages(self) -> list[PackageInfo]:
        """Returns only the packages that are currently not installed."""
        packages = await self.get_packages()
        return [p for p in packages if not p.installed]

    async def install_packages_stream(self, package_ids: list[str]) -> AsyncIterator[str]:
        """Installs requested packages, streaming live log lines."""
        id_set = set(package_ids)
        target_pkgs: list[str] = []
        for defn in DEFAULT_PACKAGE_CATALOG:
            if defn["id"] in id_set:
                target_pkgs.append(defn["package_name"])

        if not target_pkgs:
            yield "No valid packages identified for installation."
            return

        async for line in self.driver.install_system_packages(target_pkgs):
            yield line

    async def install_all_missing(self) -> AsyncIterator[str]:
        """Discovers all missing packages and streams their installation."""
        missing = await self.get_missing_packages()
        if not missing:
            yield "All required and recommended packages are already installed!"
            return

        pkg_ids = [p.id for p in missing]
        async for line in self.install_packages_stream(pkg_ids):
            yield line


package_manager = PackageManager()
