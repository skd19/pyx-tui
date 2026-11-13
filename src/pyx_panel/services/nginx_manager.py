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
    client_max_body_size: str = "256M"
    enable_immediately: bool = True
    enable_cloudflare_keepalive: bool = False
    enable_upstream_keepalive: bool = False
    upstream_keepalive_conns: int = 64
    enable_certbot_ssl: bool = False
    cloudflare_keepalive_timeout: str = "120s"
    cloudflare_keepalive_requests: int = 10000


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
        self.ensure_websocket_upgrade_conf()
        self.ensure_certbot_webroot()

    def ensure_websocket_upgrade_conf(self) -> None:
        """Ensures /etc/nginx/conf.d/websocket-upgrade.conf is present globally in http context."""
        ws_file = self.conf_d_dir / "websocket-upgrade.conf"
        if not self.driver.file_exists(ws_file):
            content = (
                "# pyx-panel: WebSocket connection upgrade mapping for persistent keep-alive proxying\n"
                "map $http_upgrade $connection_upgrade {\n"
                "    default upgrade;\n"
                "    ''      '';\n"
                "}\n"
            )
            self.driver.write_file(ws_file, content)

    def ensure_certbot_webroot(self) -> None:
        """Ensures /var/www/certbot exists for ACME HTTP-01 challenge verification."""
        webroot = Path("/var/www/certbot")
        if hasattr(self.driver, "certbot_webroot"):
            webroot = self.driver.certbot_webroot
        if not self.driver.file_exists(webroot):
            try:
                webroot.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

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
        """Generates standard or high-performance Cloudflare/Certbot Nginx reverse proxy configuration."""
        self.ensure_websocket_upgrade_conf()
        self.ensure_certbot_webroot()

        domains_str, redirect_block = self._resolve_site_domains(form.domains, form.www_handling)

        raw_upstream = form.upstream.strip()
        clean_target = re.sub(r"^https?://", "", raw_upstream).rstrip("/")
        if not raw_upstream.startswith("http://") and not raw_upstream.startswith("https://"):
            raw_upstream = f"http://{raw_upstream}"

        upstream_block = ""
        proxy_pass_target = raw_upstream

        if form.enable_upstream_keepalive:
            clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", form.name.strip()).strip("_") or "app"
            upstream_name = f"{clean_name}_backend"
            upstream_block = f"""# Upstream Backend with Persistent Keep-Alive Connection Pooling
upstream {upstream_name} {{
    server {clean_target};

    # Maintain up to {form.upstream_keepalive_conns} idle keep-alive connections to backend
    keepalive {form.upstream_keepalive_conns};
}}

"""
            proxy_pass_target = f"http://{upstream_name}"

        # Cloudflare keep-alive server directives
        cloudflare_server_directives = ""
        if form.enable_cloudflare_keepalive:
            cloudflare_server_directives = f"""
    # Cloudflare Keep-Alive Connection Pooling
    keepalive_timeout {form.cloudflare_keepalive_timeout};
    keepalive_requests {form.cloudflare_keepalive_requests};
"""

        # Location headers & proxy settings
        if form.enable_cloudflare_keepalive:
            connection_hdr = 'proxy_set_header Connection $connection_upgrade;' if form.enable_websocket else 'proxy_set_header Connection "";'
            websocket_hdr = '        # WebSocket support\n        proxy_set_header Upgrade $http_upgrade;\n' if form.enable_websocket else ''
            location_proxy_settings = f"""        # Enforce HTTP/1.1 for upstream persistent keep-alive
        proxy_http_version 1.1;

        # Client Identity & Host Forwarding
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # Cloudflare connecting IP pass-through
        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
        proxy_set_header CF-Ray $http_cf_ray;
        proxy_set_header CF-Visitor $http_cf_visitor;

        # Proxy timeouts aligned with backend
        proxy_connect_timeout 10s;
        proxy_send_timeout 15s;
        proxy_read_timeout 120s;

{websocket_hdr}        {connection_hdr}"""
        else:
            websocket_block = ""
            if form.enable_websocket:
                websocket_block = """        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";"""
            location_proxy_settings = f"""{websocket_block}
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;"""

        # Security headers
        security_headers = """    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;"""

        # ACME challenge location block
        acme_challenge_block = """    # Certbot ACME HTTP-01 challenge validation directory
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }"""

        # Security filters (hidden files & sensitive extensions)
        security_filters = """    # Security: Block hidden files (.env, .git, etc.)
    location ~ /\\.(?!well-known) {
        deny all;
        return 404;
    }

    # Security: Block sensitive extensions
    location ~* \\.(env|git|bak|sql|log|yml|yaml|ini|conf|sh|key|pem|crt)$ {
        deny all;
        return 404;
    }"""

        if form.enable_certbot_ssl:
            first_dom = [d.strip() for d in re.split(r"[\s,]+", form.domains.strip()) if d.strip()][0]
            root_dom, _ = parse_domain_and_www_alias(first_dom)
            cert_domain = root_dom or first_dom

            cert_path = f"/etc/letsencrypt/live/{cert_domain}/fullchain.pem"
            key_path = f"/etc/letsencrypt/live/{cert_domain}/privkey.pem"

            config = f"""{upstream_block}# 1. Redirect all HTTP traffic to HTTPS (with ACME challenge pass-through)
server {{
    listen 80;
    listen [::]:80;
    server_name {domains_str};

{acme_challenge_block}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# 2. Primary HTTPS Server (Port 443 with HTTP/2 & Cloudflare Keep-Alive)
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domains_str};

    # Certbot Let's Encrypt Certificates
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};

    # Modern TLS Security & Rapid Resumption
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    # SSL Session Caching (Rapid 0-RTT/1-RTT Session Resumption)
    ssl_session_cache shared:SSL:20m;
    ssl_session_timeout 1d;
    ssl_session_tickets on;
{cloudflare_server_directives}
{security_headers}

    client_max_body_size {form.client_max_body_size};

{security_filters}

    location / {{
        proxy_pass {proxy_pass_target};
{location_proxy_settings.lstrip()}
    }}
}}
"""
        else:
            config = f"""{upstream_block}{redirect_block}server {{
    listen 80;
    server_name {domains_str};

    client_max_body_size {form.client_max_body_size};
{cloudflare_server_directives}
{acme_challenge_block}

{security_filters}

{security_headers}

    location / {{
        proxy_pass {proxy_pass_target};
{location_proxy_settings.lstrip()}
    }}
}}
"""
        return config

    def get_config_snippet(self, snippet_type: str, domain: str = "yourdomain.com", upstream: str = "127.0.0.1:8080") -> str:
        """Returns standard Nginx configuration blocks for 1-click editor insertion."""
        clean_target = re.sub(r"^https?://", "", upstream).rstrip("/")

        if snippet_type == "cloudflare-keepalive":
            return (
                "    # Cloudflare Keep-Alive: paste inside server { } block\n"
                "    keepalive_timeout 120s;\n"
                "    keepalive_requests 10000;\n"
            )

        if snippet_type == "cloudflare-proxy-headers":
            return (
                "        # Cloudflare connecting IP pass-through: paste inside location / { } block\n"
                "        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;\n"
                "        proxy_set_header CF-Ray $http_cf_ray;\n"
                "        proxy_set_header CF-Visitor $http_cf_visitor;\n\n"
                "        # Proxy timeouts aligned with Go backend\n"
                "        proxy_connect_timeout 10s;\n"
                "        proxy_send_timeout 15s;\n"
                "        proxy_read_timeout 120s;\n"
            )

        if snippet_type == "upstream-keepalive":
            return (
                "# Upstream Go Backend with Persistent Keep-Alive Connection Pooling\n"
                "upstream go_backend {\n"
                f"    server {clean_target};\n\n"
                "    # Maintain up to 64 idle keep-alive connections to the Go backend\n"
                "    keepalive 64;\n"
                "}\n"
            )

        if snippet_type == "certbot-ssl":
            root_dom, www_dom = parse_domain_and_www_alias(domain)
            doms = f"{root_dom or domain} {www_dom}" if www_dom else domain
            return (
                "# 1. Redirect all HTTP traffic to HTTPS (with Certbot ACME challenge)\n"
                "server {\n"
                "    listen 80;\n"
                "    listen [::]:80;\n"
                f"    server_name {doms};\n\n"
                "    # Certbot ACME HTTP-01 challenge validation directory\n"
                "    location /.well-known/acme-challenge/ {\n"
                "        root /var/www/certbot;\n"
                "    }\n\n"
                "    location / {\n"
                "        return 301 https://$host$request_uri;\n"
                "    }\n"
                "}\n\n"
                "# 2. Primary HTTPS Server (Port 443 with HTTP/2)\n"
                "server {\n"
                "    listen 443 ssl http2;\n"
                "    listen [::]:443 ssl http2;\n"
                f"    server_name {doms};\n\n"
                f"    ssl_certificate /etc/letsencrypt/live/{root_dom or domain}/fullchain.pem;\n"
                f"    ssl_certificate_key /etc/letsencrypt/live/{root_dom or domain}/privkey.pem;\n\n"
                "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                "    ssl_prefer_server_ciphers off;\n"
                "    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';\n\n"
                "    ssl_session_cache shared:SSL:20m;\n"
                "    ssl_session_timeout 1d;\n"
                "    ssl_session_tickets on;\n"
                "}\n"
            )

        if snippet_type == "full-go-template":
            form = ReverseProxyForm(
                name="go-android",
                domains=domain,
                upstream=upstream,
                enable_websocket=True,
                client_max_body_size="256M",
                enable_cloudflare_keepalive=True,
                enable_upstream_keepalive=True,
                upstream_keepalive_conns=64,
                enable_certbot_ssl=True,
            )
            return self.generate_reverse_proxy_config(form)

        return ""

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

    def remove_ssl_from_config(self, content: str) -> str:
        """
        Parses Nginx configuration and removes SSL/TLS directives:
        - Eliminates Certbot-generated HTTP->HTTPS redirect server blocks.
        - Converts 'listen 443 ssl' to 'listen 80'.
        - Converts 'listen [::]:443 ssl' to 'listen [::]:80'.
        - Removes ssl_certificate, ssl_certificate_key, ssl_dhparam, options-ssl-nginx.conf, and other SSL directives.
        - Strips Certbot if-redirect rules.
        - Ensures every remaining server block has a 'listen 80;' directive.
        """
        blocks: list[str] = []
        i = 0
        n = len(content)
        while i < n:
            m = re.search(r"\bserver\s*\{", content[i:])
            if not m:
                break
            start = i + m.start()
            brace_count = 0
            j = i + m.end() - 1
            while j < n:
                if content[j] == "{":
                    brace_count += 1
                elif content[j] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        blocks.append(content[start:j + 1])
                        i = j + 1
                        break
                j += 1
            else:
                break

        if not blocks:
            return content

        cleaned_blocks: list[str] = []
        for b in blocks:
            # Check if block is purely a certbot redirect block
            is_certbot_redirect = (
                "# managed by Certbot" in b
                and ("return 301 https:" in b or "return 404" in b)
                and not ("proxy_pass" in b or "fastcgi_pass" in b or re.search(r"\broot\s+", b))
            )
            if is_certbot_redirect:
                continue

            lines = b.splitlines()
            new_lines: list[str] = []
            has_listen_80 = any(re.search(r"\blisten\s+([^;]*\b80\b)", l) for l in lines)
            has_listen_80_v6 = any(re.search(r"\blisten\s+\[::\]:80\b", l) for l in lines)

            skip_if_block = False
            skip_brace_depth = 0

            for line in lines:
                stripped = line.strip()

                # Handle if ($host = ...) { return 301 https:... } # managed by Certbot
                if re.search(r"if\s*\(\$host\s*=.*https:", stripped) or (
                    "if ($host =" in stripped and "# managed by Certbot" in line
                ):
                    skip_if_block = True
                    skip_brace_depth = line.count("{") - line.count("}")
                    continue
                if skip_if_block:
                    skip_brace_depth += line.count("{") - line.count("}")
                    if skip_brace_depth <= 0:
                        skip_if_block = False
                    continue

                # Remove Certbot and SSL directives
                if any(
                    stripped.startswith(prefix)
                    for prefix in [
                        "ssl_certificate",
                        "ssl_certificate_key",
                        "ssl_dhparam",
                        "ssl_trusted_certificate",
                        "ssl_protocols",
                        "ssl_ciphers",
                        "ssl_prefer_server_ciphers",
                        "ssl_session_",
                        "ssl_stapling",
                    ]
                ):
                    continue
                if "include /etc/letsencrypt/" in stripped:
                    continue

                # Transform listen 443 ssl -> listen 80
                if re.search(r"\blisten\s+.*443.*ssl", stripped):
                    is_v6 = "[::]" in stripped
                    if is_v6:
                        if not has_listen_80_v6:
                            indent = line[: len(line) - len(line.lstrip())]
                            new_lines.append(f"{indent}listen [::]:80;")
                            has_listen_80_v6 = True
                    else:
                        if not has_listen_80:
                            indent = line[: len(line) - len(line.lstrip())]
                            new_lines.append(f"{indent}listen 80;")
                            has_listen_80 = True
                    continue

                # Strip '# managed by Certbot' comments from line
                cleaned_line = re.sub(r"\s*#\s*managed by Certbot", "", line)
                new_lines.append(cleaned_line)

            cleaned_block = "\n".join(new_lines)
            # Ensure the block has at least listen 80
            if not re.search(r"\blisten\s+[^;]*80", cleaned_block):
                cleaned_block = re.sub(
                    r"(\bserver\s*\{)", r"\1\n    listen 80;", cleaned_block, count=1
                )

            cleaned_blocks.append(cleaned_block)

        return "\n\n".join(cleaned_blocks).strip() + "\n"

    def find_sites_for_domain_or_cert(self, domain_or_cert: str) -> list[SiteSummary]:
        """
        Discovers all sites matching a domain or certificate name.
        Matches by domain names (including apex/www aliases) or certificate live path reference.
        """
        target = domain_or_cert.strip().lower()
        root_dom, www_dom = parse_domain_and_www_alias(target)
        target_domains = {target}
        if root_dom:
            target_domains.add(root_dom)
        if www_dom:
            target_domains.add(www_dom)

        matching_sites: list[SiteSummary] = []
        for site in self.list_sites():
            site_domains = {d.lower() for d in site.domains}
            # Check domain intersection
            if site_domains & target_domains:
                matching_sites.append(site)
                continue
            # Check if config references the certificate live directory
            if f"/etc/letsencrypt/live/{target}/" in site.content or (
                root_dom and f"/etc/letsencrypt/live/{root_dom}/" in site.content
            ):
                matching_sites.append(site)
                continue

        return matching_sites

    async def remove_ssl_from_site(self, name: str) -> tuple[bool, str]:
        """
        Removes SSL directives from a site in sites-available (and sites-enabled),
        validates with nginx -t, rolls back on syntax errors, and reloads Nginx.
        """
        filename = self._sanitize_name(name)
        available_path = self.available_dir / filename
        enabled_path = self.enabled_dir / filename

        if not self.driver.file_exists(available_path):
            return False, f"Site '{name}' not found in sites-available"

        original_content = self.driver.read_file(available_path)
        is_enabled = self.driver.file_exists(enabled_path)

        cleaned_content = self.remove_ssl_from_config(original_content)
        if cleaned_content.strip() == original_content.strip():
            return True, f"Site '{name}' already has no SSL directives"

        # Write cleaned content
        self.driver.write_file(available_path, cleaned_content)
        if is_enabled:
            self.driver.write_file(enabled_path, cleaned_content)

        # Pre-validate with nginx -t
        is_valid, msg = await self.driver.test_nginx()
        if not is_valid:
            # Atomic rollback
            self.driver.write_file(available_path, original_content)
            if is_enabled:
                self.driver.write_file(enabled_path, original_content)
            return False, f"Cannot remove SSL: Nginx syntax error: {msg}"

        # Reload Nginx
        await self.driver.reload_nginx()
        return True, f"SSL removed from site '{name}'. Site is now served over HTTP."

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
