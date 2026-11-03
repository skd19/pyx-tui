"""Nginx site configuration and virtual host manager."""
from __future__ import annotations

import re
from pathlib import Path
from pydantic import BaseModel, Field
from pyx_panel.config import settings
from pyx_panel.core import get_driver


class SiteSummary(BaseModel):
    """Summary of an Nginx site configuration."""
    name: str
    filename: str
    enabled: bool
    domains: list[str] = Field(default_factory=list)
    proxy_pass: str = ""
    ssl_enabled: bool = False
    content: str = ""


class ReverseProxyForm(BaseModel):
    """Input form for generating an Nginx reverse proxy site."""
    name: str
    domains: str  # Space-separated or comma-separated
    upstream: str  # e.g. "http://127.0.0.1:8080"
    enable_websocket: bool = True
    client_max_body_size: str = "50M"
    enable_immediately: bool = True


class StaticSiteForm(BaseModel):
    """Input form for generating a static site configuration."""
    name: str
    domains: str
    root_path: str  # e.g. "/var/www/mysite"
    spa_fallback: bool = True
    enable_immediately: bool = True


class NginxManager:
    """Manages Nginx sites-available and sites-enabled configurations safely."""

    def __init__(self) -> None:
        self.driver = get_driver()
        self.available_dir = settings.nginx_sites_available
        self.enabled_dir = settings.nginx_sites_enabled

    def _sanitize_name(self, name: str) -> str:
        """Sanitizes site name to a safe filename."""
        cleaned = re.sub(r"[^a-zA-Z0-9_\.-]", "_", name.strip())
        if not cleaned.endswith(".conf"):
            cleaned += ".conf"
        return cleaned

    def list_sites(self) -> list[SiteSummary]:
        """Lists all sites from sites-available with enabled status and metadata."""
        filenames = self.driver.list_dir(self.available_dir)
        sites: list[SiteSummary] = []

        for fn in sorted(filenames):
            if fn.startswith(".") or fn.endswith(".tmp") or fn.endswith(".bak"):
                continue

            available_path = self.available_dir / fn
            enabled_path = self.enabled_dir / fn
            content = self.driver.read_file(available_path)

            is_enabled = self.driver.file_exists(enabled_path)

            # Parse domain names
            domains: list[str] = []
            m_server = re.findall(r"server_name\s+([^;]+);", content)
            for s in m_server:
                for d in s.split():
                    d_clean = d.strip()
                    if d_clean and d_clean != "_":
                        domains.append(d_clean)

            # Parse proxy_pass
            m_proxy = re.search(r"proxy_pass\s+([^;]+);", content)
            proxy_pass = m_proxy.group(1).strip() if m_proxy else ""

            # Check SSL
            ssl_enabled = bool(
                re.search(r"listen\s+.*443\s+ssl", content)
                or "ssl_certificate " in content
            )

            name = fn[:-5] if fn.endswith(".conf") else fn

            sites.append(
                SiteSummary(
                    name=name,
                    filename=fn,
                    enabled=is_enabled,
                    domains=domains,
                    proxy_pass=proxy_pass,
                    ssl_enabled=ssl_enabled,
                    content=content,
                )
            )

        return sites

    def get_site(self, name: str) -> SiteSummary | None:
        """Fetch single site configuration by name."""
        filename = self._sanitize_name(name)
        available_path = self.available_dir / filename
        if not self.driver.file_exists(available_path):
            return None

        content = self.driver.read_file(available_path)
        enabled_path = self.enabled_dir / filename
        is_enabled = self.driver.file_exists(enabled_path)

        domains: list[str] = []
        m_server = re.findall(r"server_name\s+([^;]+);", content)
        for s in m_server:
            for d in s.split():
                if d.strip() and d.strip() != "_":
                    domains.append(d.strip())

        m_proxy = re.search(r"proxy_pass\s+([^;]+);", content)
        proxy_pass = m_proxy.group(1).strip() if m_proxy else ""
        ssl_enabled = bool(
            re.search(r"listen\s+.*443\s+ssl", content) or "ssl_certificate " in content
        )

        site_name = filename[:-5] if filename.endswith(".conf") else filename
        return SiteSummary(
            name=site_name,
            filename=filename,
            enabled=is_enabled,
            domains=domains,
            proxy_pass=proxy_pass,
            ssl_enabled=ssl_enabled,
            content=content,
        )

    def generate_reverse_proxy_config(self, form: ReverseProxyForm) -> str:
        """Generates standard Nginx reverse proxy configuration."""
        # Clean domain string
        domain_list = re.split(r"[\s,]+", form.domains.strip())
        domains_str = " ".join(d for d in domain_list if d) or "_"

        upstream = form.upstream.strip()
        if not upstream.startswith("http://") and not upstream.startswith("https://"):
            upstream = f"http://{upstream}"

        websocket_block = ""
        if form.enable_websocket:
            websocket_block = """        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";"""

        config = f"""server {{
    listen 80;
    server_name {domains_str};

    client_max_body_size {form.client_max_body_size};

    location / {{
        proxy_pass {upstream};
{websocket_block}
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;
    }}
}}
"""
        return config

    def generate_static_config(self, form: StaticSiteForm) -> str:
        """Generates standard static website configuration."""
        domain_list = re.split(r"[\s,]+", form.domains.strip())
        domains_str = " ".join(d for d in domain_list if d) or "_"
        root = form.root_path.strip()

        try_files = "try_files $uri $uri/ /index.html;" if form.spa_fallback else "try_files $uri $uri/ =404;"

        config = f"""server {{
    listen 80;
    server_name {domains_str};

    root {root};
    index index.html index.htm;

    location / {{
        {try_files}
    }}

    location ~* \\.(?:css|js|jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm|htc|woff|woff2|ttf)$ {{
        expires 1M;
        access_log off;
        add_header Cache-Control "public";
    }}
}}
"""
        return config

    async def save_and_validate_site(
        self,
        name: str,
        content: str,
        enable_if_new: bool = False,
    ) -> tuple[bool, str]:
        """
        Saves a site configuration safely. Validates with nginx -t.
        Reverts the changes if validation fails.
        """
        filename = self._sanitize_name(name)
        available_path = self.available_dir / filename
        enabled_path = self.enabled_dir / filename

        # Backup old content if exists
        old_content = self.driver.read_file(available_path)
        was_previously_enabled = self.driver.file_exists(enabled_path)

        # Write new content
        self.driver.write_file(available_path, content)

        # In order for nginx -t to validate this config, it must be linked in sites-enabled
        self.driver.create_symlink(available_path, enabled_path)

        # Validate with nginx -t
        is_valid, error_msg = await self.driver.test_nginx()
        if not is_valid:
            # Revert
            if old_content:
                self.driver.write_file(available_path, old_content)
                if not was_previously_enabled:
                    self.driver.remove_symlink(enabled_path)
            else:
                self.driver.delete_file(available_path)
                self.driver.remove_symlink(enabled_path)

            return False, f"Nginx validation failed: {error_msg}"

        # If it was not previously enabled and caller did not request enable, remove the test symlink
        if not was_previously_enabled and not enable_if_new:
            self.driver.remove_symlink(enabled_path)

        # Safe reload
        await self.driver.reload_nginx()
        return True, "Site configuration saved and applied successfully"

    async def enable_site(self, name: str) -> tuple[bool, str]:
        """Enable site by creating symlink in sites-enabled and reloading."""
        filename = self._sanitize_name(name)
        available_path = self.available_dir / filename
        enabled_path = self.enabled_dir / filename

        if not self.driver.file_exists(available_path):
            return False, f"Site {filename} not found in sites-available"

        self.driver.create_symlink(available_path, enabled_path)

        is_valid, msg = await self.driver.test_nginx()
        if not is_valid:
            self.driver.remove_symlink(enabled_path)
            return False, f"Cannot enable site: Nginx syntax error: {msg}"

        await self.driver.reload_nginx()
        return True, f"Site {filename} enabled"

    async def disable_site(self, name: str) -> tuple[bool, str]:
        """Disable site by removing symlink in sites-enabled and reloading."""
        filename = self._sanitize_name(name)
        enabled_path = self.enabled_dir / filename

        if not self.driver.file_exists(enabled_path):
            return True, f"Site {filename} already disabled"

        self.driver.remove_symlink(enabled_path)
        await self.driver.reload_nginx()
        return True, f"Site {filename} disabled"

    async def delete_site(self, name: str) -> tuple[bool, str]:
        """Delete site from sites-enabled and sites-available."""
        filename = self._sanitize_name(name)
        available_path = self.available_dir / filename
        enabled_path = self.enabled_dir / filename

        self.driver.remove_symlink(enabled_path)
        self.driver.delete_file(available_path)

        await self.driver.reload_nginx()
        return True, f"Site {filename} deleted"


nginx_manager = NginxManager()
