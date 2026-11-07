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


def parse_domain_and_www_alias(domain: str) -> tuple[str, str | None]:
    """
    Given a domain, returns (apex_or_root_domain, www_domain).
    If the domain cannot have a www alias (e.g. localhost, IP address),
    returns (domain, None).
    """
    d = domain.strip().lower()
    if not d or d == "_" or d == "localhost" or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) or ":" in d:
        return d, None

    if d.startswith("www."):
        root = d[4:]
        return root, d
    else:
        parts = d.split(".")
        if len(parts) >= 2:
            return d, f"www.{d}"
        return d, None


class ReverseProxyForm(BaseModel):
    """Input form for generating an Nginx reverse proxy site."""
    name: str
    domains: str  # Space-separated or comma-separated
    upstream: str  # e.g. "http://127.0.0.1:8080"
    www_handling: str = "none"  # "none", "redirect_to_www", "redirect_to_root", "both"
    enable_websocket: bool = True
    client_max_body_size: str = "50M"
    enable_immediately: bool = True


class StaticSiteForm(BaseModel):
    """Input form for generating a static site configuration."""
    name: str
    domains: str
    root_path: str  # e.g. "/var/www/mysite"
    www_handling: str = "none"  # "none", "redirect_to_www", "redirect_to_root", "both"
    spa_fallback: bool = True
    enable_immediately: bool = True


class NginxManager:
    """Manages Nginx sites-available and sites-enabled configurations safely."""

    def __init__(self) -> None:
        self.driver = get_driver()
        self.available_dir = settings.nginx_sites_available
        self.enabled_dir = settings.nginx_sites_enabled
        self.conf_d_dir = settings.nginx_conf_d

    def _sanitize_name(self, name: str) -> str:
        """Sanitizes site name to a safe filename."""
        cleaned = re.sub(r"[^a-zA-Z0-9_\.-]", "_", name.strip())
        if self.driver.file_exists(self.available_dir / cleaned):
            return cleaned
        if not cleaned.endswith(".conf"):
            cleaned += ".conf"
        return cleaned

    def list_sites(self) -> list[SiteSummary]:
        """Lists all sites from sites-available with enabled status and metadata."""
        filenames = self.driver.list_dir(self.available_dir)
        sites: list[SiteSummary] = []

        for fn in sorted(filenames):
            if (
                fn.startswith(".")
                or fn.endswith(".tmp")
                or fn.endswith(".bak")
                or fn in ("default", "default.conf", "default-deny.conf")
            ):
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

    def _resolve_site_domains(self, domains_input: str, www_handling: str) -> tuple[str, str]:
        """
        Resolves domain inputs and www handling options.
        Returns: (main_domains_str, redirect_block_str)
        """
        raw_list = [d.strip() for d in re.split(r"[\s,]+", domains_input.strip()) if d.strip()]
        if not raw_list:
            return "_", ""

        primary = raw_list[0]
        root_dom, www_dom = parse_domain_and_www_alias(primary)

        if not www_dom or not root_dom:
            return " ".join(raw_list), ""

        extra_domains = [d for d in raw_list[1:] if d != root_dom and d != www_dom]

        if www_handling == "redirect_to_www":
            # www is the main domain; root redirects to www
            main_server_names = [www_dom] + extra_domains
            redirect_block = f"""server {{
    listen 80;
    server_name {root_dom};
    return 301 $scheme://{www_dom}$request_uri;
}}

"""
            return " ".join(main_server_names), redirect_block

        elif www_handling == "redirect_to_root":
            # root is the main domain; www redirects to root
            main_server_names = [root_dom] + extra_domains
            redirect_block = f"""server {{
    listen 80;
    server_name {www_dom};
    return 301 $scheme://{root_dom}$request_uri;
}}

"""
            return " ".join(main_server_names), redirect_block

        elif www_handling == "both":
            # Both served on the same main block without redirect
            names = [root_dom, www_dom] + extra_domains
            if primary.startswith("www."):
                names = [www_dom, root_dom] + extra_domains
            return " ".join(names), ""

        # Default: "none" - exact domains entered
        return " ".join(raw_list), ""

    def generate_reverse_proxy_config(self, form: ReverseProxyForm) -> str:
        """Generates standard Nginx reverse proxy configuration."""
        domains_str, redirect_block = self._resolve_site_domains(form.domains, form.www_handling)

        upstream = form.upstream.strip()
        if not upstream.startswith("http://") and not upstream.startswith("https://"):
            upstream = f"http://{upstream}"

        websocket_block = ""
        if form.enable_websocket:
            websocket_block = """        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";"""

        config = f"""{redirect_block}server {{
    listen 80;
    server_name {domains_str};

    client_max_body_size {form.client_max_body_size};

    # Security: Block hidden files (.env, .git, etc.)
    location ~ /\\.(?!well-known) {{
        deny all;
        return 404;
    }}

    # Security: Block sensitive extensions
    location ~* \\.(env|git|bak|sql|log|yml|yaml|ini|conf|sh|key|pem|crt)$ {{
        deny all;
        return 404;
    }}

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

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
        domains_str, redirect_block = self._resolve_site_domains(form.domains, form.www_handling)
        root = form.root_path.strip()

        try_files = "try_files $uri $uri/ /index.html;" if form.spa_fallback else "try_files $uri $uri/ =404;"

        config = f"""{redirect_block}server {{
    listen 80;
    server_name {domains_str};

    root {root};
    index index.html index.htm;

    # Security: Block hidden files (.env, .git, etc.)
    location ~ /\\.(?!well-known) {{
        deny all;
        return 404;
    }}

    # Security: Block sensitive extensions
    location ~* \\.(env|git|bak|sql|log|yml|yaml|ini|conf|sh|key|pem|crt)$ {{
        deny all;
        return 404;
    }}

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

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

        # In order for nginx -t to validate this config and for site to be enabled, copy to sites-enabled
        self.driver.copy_file(available_path, enabled_path)

        # Validate with nginx -t
        is_valid, error_msg = await self.driver.test_nginx()
        if not is_valid:
            # Revert
            if old_content:
                self.driver.write_file(available_path, old_content)
                if was_previously_enabled:
                    self.driver.copy_file(available_path, enabled_path)
                else:
                    self.driver.delete_file(enabled_path)
            else:
                self.driver.delete_file(available_path)
                self.driver.delete_file(enabled_path)

            return False, f"Nginx validation failed: {error_msg}"

        # If it was not previously enabled and caller did not request enable, remove from sites-enabled
        if not was_previously_enabled and not enable_if_new:
            self.driver.delete_file(enabled_path)

        # Safe reload
        await self.driver.reload_nginx()
        return True, "Site configuration saved and applied successfully"

    async def enable_site(self, name: str) -> tuple[bool, str]:
        """Enable site by copying config into sites-enabled and reloading."""
        filename = self._sanitize_name(name)
        available_path = self.available_dir / filename
        enabled_path = self.enabled_dir / filename

        if not self.driver.file_exists(available_path):
            return False, f"Site {filename} not found in sites-available"

        self.driver.copy_file(available_path, enabled_path)

        is_valid, msg = await self.driver.test_nginx()
        if not is_valid:
            self.driver.delete_file(enabled_path)
            return False, f"Cannot enable site: Nginx syntax error: {msg}"

        await self.driver.reload_nginx()
        return True, f"Site {filename} enabled"

    async def disable_site(self, name: str) -> tuple[bool, str]:
        """Disable site by removing from sites-enabled and reloading."""
        filename = self._sanitize_name(name)
        enabled_path = self.enabled_dir / filename

        if not self.driver.file_exists(enabled_path):
            return True, f"Site {filename} already disabled"

        self.driver.delete_file(enabled_path)
        await self.driver.reload_nginx()
        return True, f"Site {filename} disabled"

    async def delete_site(self, name: str) -> tuple[bool, str]:
        """Delete site from sites-enabled and sites-available."""
        filename = self._sanitize_name(name)
        available_path = self.available_dir / filename
        enabled_path = self.enabled_dir / filename

        self.driver.delete_file(enabled_path)
        self.driver.delete_file(available_path)

        await self.driver.reload_nginx()
        return True, f"Site {filename} deleted"

    def is_default_deny_active(self) -> bool:
        """Checks if the direct IP reject (default-deny catch-all) is currently enabled."""
        return self.driver.file_exists(self.enabled_dir / "default-deny.conf")

    async def enable_default_deny(self) -> tuple[bool, str]:
        """
        Creates and activates Nginx catch-all default_server to reject direct IP hits
        and unknown hostnames with return 444 (HTTP) and ssl_reject_handshake on (HTTPS).
        Automatically resolves conflicting Ubuntu default site and selects compatible directives.
        """
        # 1. Check for conflicting default_server in active user sites
        conflicts: list[str] = []
        default_was_enabled = False
        default_file = None

        for fname in self.driver.list_dir(self.enabled_dir):
            if fname in ("default", "default.conf"):
                default_was_enabled = True
                default_file = fname
                continue
            if fname == "default-deny.conf":
                continue

            path = self.enabled_dir / fname
            content = self.driver.read_file(path)
            if "default_server" in content:
                conflicts.append(fname)

        if conflicts:
            return (
                False,
                f"Conflicting 'default_server' found in active site(s): {', '.join(conflicts)}. "
                "Please remove 'default_server' from those sites before enabling Direct IP Drop.",
            )

        # 2. If Ubuntu boilerplate 'default' exists in sites-enabled, temporarily remove it
        # so default-deny can bind default_server on port 80/443 without collision
        if default_was_enabled and default_file:
            self.driver.delete_file(self.enabled_dir / default_file)

        # 3. Candidate configs from most advanced to universal fallback
        candidates = [
            (
                "IPv4/IPv6 + HTTPS reject",
                """server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
""",
            ),
            (
                "IPv4 + HTTPS reject",
                """server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
""",
            ),
            (
                "IPv4/IPv6 HTTP catch-all",
                """server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
""",
            ),
            (
                "IPv4 HTTP catch-all",
                """server {
    listen 80 default_server;
    server_name _;
    return 444;
}
""",
            ),
        ]

        last_err = ""
        for desc, conf in candidates:
            success, msg = await self.save_and_validate_site("default-deny", conf, enable_if_new=True)
            if success:
                return True, f"Direct IP reject enabled ({desc}): raw VPS IP connections and unknown hostnames dropped with 444"
            last_err = msg

        # If all candidates failed, restore default site if it was previously enabled
        if default_was_enabled and default_file:
            avail = self.available_dir / default_file
            if self.driver.file_exists(avail):
                self.driver.copy_file(avail, self.enabled_dir / default_file)

        await self.disable_default_deny()
        return False, last_err

    async def disable_default_deny(self) -> tuple[bool, str]:
        """Disables the direct IP reject catch-all."""
        return await self.disable_site("default-deny")

    def is_security_guard_active(self) -> bool:
        """Checks if the global security guard configuration is currently active in conf.d."""
        return self.driver.file_exists(self.conf_d_dir / "pyx-security-guard.conf")

    def is_directive_declared_globally(self, directive: str) -> bool:
        """
        Checks whether a given directive (e.g. 'server_tokens', 'keepalive_timeout')
        is already declared in nginx.conf or existing files in conf.d.
        """
        pattern = re.compile(rf"^\s*{re.escape(directive)}\b")

        # 1. Check main nginx.conf if present
        main_conf = settings.nginx_main_config
        if self.driver.file_exists(main_conf):
            try:
                content = self.driver.read_file(main_conf)
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if pattern.match(stripped):
                        return True
            except Exception:
                pass

        # 2. Check other files in conf.d
        try:
            if self.conf_d_dir.exists():
                for p in self.conf_d_dir.iterdir():
                    if p.name == "pyx-security-guard.conf" or not p.is_file():
                        continue
                    content = self.driver.read_file(p)
                    for line in content.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        if pattern.match(stripped):
                            return True
        except Exception:
            pass

        return False

    def _build_security_guard_content(self, omit_directives: set[str] | None = None) -> str:
        """Constructs pyx-security-guard.conf while omitting duplicate or conflicting directives."""
        omit = set(omit_directives or [])
        lines = [
            "# Pyx Panel Global Security Hardening Guard",
            "# Generated automatically by Pyx Panel Security Center",
            "",
            "# 1. Hide Nginx Version Signature",
        ]

        if "server_tokens" in omit or self.is_directive_declared_globally("server_tokens"):
            lines.append("# server_tokens off; # (omitted: already defined in host Nginx configuration)")
        else:
            lines.append("server_tokens off;")

        lines.extend([
            "",
            "# 2. Rate Limiting Zones (DDoS, Slowloris, Brute Force protection)",
            "limit_req_zone $binary_remote_addr zone=pyx_general_limit:10m rate=30r/s;",
            "limit_req_zone $binary_remote_addr zone=pyx_login_limit:10m rate=5r/m;",
            "limit_conn_zone $binary_remote_addr zone=pyx_addr_conn:10m;",
            "",
            "# 3. Connection & Request Timeouts (Mitigates Slowloris & idle socket starvation)",
        ])

        for timeout_directive, timeout_val in [
            ("client_body_timeout", "15s"),
            ("client_header_timeout", "15s"),
            ("send_timeout", "15s"),
        ]:
            if timeout_directive in omit or self.is_directive_declared_globally(timeout_directive):
                lines.append(f"# {timeout_directive} {timeout_val}; # (omitted: already defined in host Nginx configuration)")
            else:
                lines.append(f"{timeout_directive} {timeout_val};")

        # keepalive_timeout: Standard in Ubuntu/Debian /etc/nginx/nginx.conf ('keepalive_timeout 65;').
        # Including it in conf.d duplicates the directive at the http level unless absent globally.
        if "keepalive_timeout" in omit or self.is_directive_declared_globally("keepalive_timeout"):
            lines.append("# keepalive_timeout 30s; # (omitted: already defined in host Nginx configuration)")
        else:
            lines.append("keepalive_timeout 30s;")

        lines.append("")
        return "\n".join(lines)

    async def apply_security_guard(self) -> tuple[bool, str]:
        """
        Creates and activates global security guard config in /etc/nginx/conf.d/pyx-security-guard.conf.
        Hides nginx server tokens, sets Slowloris client timeouts, and configures rate-limiting zones.
        Gracefully detects and reconciles duplicate directives defined in host nginx.conf.
        """
        target_path = self.conf_d_dir / "pyx-security-guard.conf"
        old_content = self.driver.read_file(target_path) if self.driver.file_exists(target_path) else None

        omitted_directives: set[str] = set()
        max_reconcile_attempts = 5

        # Regex to detect duplicate directive error from nginx -t
        # Example: '2026/11/05 20:32:31 [emerg] 63939#63939: "server_tokens" directive is duplicate in /etc/nginx/conf.d/pyx-security-guard.conf:5 nginx: configuration file /etc/nginx/nginx.conf test failed'
        dup_pattern = re.compile(r'"([a-zA-Z0-9_]+)" directive is duplicate in .*pyx-security-guard\.conf')

        for _ in range(max_reconcile_attempts):
            guard_content = self._build_security_guard_content(omitted_directives)
            self.driver.write_file(target_path, guard_content)

            is_valid, msg = await self.driver.test_nginx()
            if is_valid:
                await self.driver.reload_nginx()
                if omitted_directives:
                    reconciled_str = ", ".join(sorted(omitted_directives))
                    return True, f"Nginx Global Security Guard applied successfully (reconciled duplicate host directives: {reconciled_str})"
                return True, "Nginx Global Security Guard applied successfully"

            # Check if failure is due to a duplicate directive in pyx-security-guard.conf
            dup_match = dup_pattern.search(msg)
            if dup_match:
                dup_directive = dup_match.group(1)
                if dup_directive not in omitted_directives:
                    omitted_directives.add(dup_directive)
                    continue  # Retry with newly omitted directive

            # If not a duplicate directive or already omitted and still failing, abort and rollback
            if old_content is not None:
                self.driver.write_file(target_path, old_content)
            else:
                self.driver.delete_file(target_path)
            return False, f"Nginx validation failed with security guard: {msg}"

        # If loop exhausted
        if old_content is not None:
            self.driver.write_file(target_path, old_content)
        else:
            self.driver.delete_file(target_path)
        return False, "Nginx validation failed: maximum reconciliation attempts exceeded for duplicate directives"

    async def revert_security_guard(self) -> tuple[bool, str]:
        """Removes global security guard config from conf.d and reloads Nginx."""
        target_path = self.conf_d_dir / "pyx-security-guard.conf"
        if not self.driver.file_exists(target_path):
            return True, "Nginx Security Guard is not currently active"

        self.driver.delete_file(target_path)
        is_valid, msg = await self.driver.test_nginx()
        if not is_valid:
            return False, f"Nginx validation failed after reverting security guard: {msg}"

        await self.driver.reload_nginx()
        return True, "Nginx Global Security Guard disabled"


nginx_manager = NginxManager()
