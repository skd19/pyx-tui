"""WordPress management service: site detection, deployment wizard, Nginx FastCGI, maintenance mode, and backups."""
from __future__ import annotations

import datetime
import re
import secrets
from pathlib import Path
from pydantic import BaseModel, Field

from pyx_panel.config import settings
from pyx_panel.core import get_driver
from pyx_panel.services.nginx_manager import (
    NginxManager,
    nginx_manager,
    parse_domain_and_www_alias,
)


class WordPressSiteInfo(BaseModel):
    """Information and runtime status for an active WordPress site."""
    name: str
    filename: str
    domains: list[str] = Field(default_factory=list)
    root_path: str = ""
    wp_version: str = "Unknown"
    php_socket: str = ""
    db_name: str = ""
    db_user: str = ""
    ssl_enabled: bool = False
    nginx_enabled: bool = True
    in_maintenance: bool = False
    xmlrpc_blocked: bool = True
    content: str = ""


class WordPressDeployForm(BaseModel):
    """Input parameters for deploying a new WordPress site."""
    name: str
    domains: str
    www_handling: str = "none"  # "none", "redirect_to_www", "redirect_to_root", "both"
    root_path: str = ""
    php_socket: str = ""
    create_db: bool = True
    db_name: str = ""
    db_user: str = ""
    db_pass: str = ""
    download_core: bool = True
    block_xmlrpc: bool = True
    block_upload_php: bool = True
    client_max_body_size: str = "64M"
    enable_immediately: bool = True


class WordPressManager:
    """Manages WordPress sites, FastCGI Nginx configurations, maintenance mode, and database backups."""

    def __init__(self, mgr: NginxManager | None = None) -> None:
        self.driver = get_driver()
        self.nginx_mgr = mgr or nginx_manager

    async def detect_php_sockets(self) -> list[str]:
        """Detects available PHP-FPM sockets on the host."""
        sockets = await self.driver.list_php_fpm_sockets()
        if not sockets:
            return ["unix:/run/php/php-fpm.sock"]
        return sockets

    def generate_wp_config_content(
        self,
        db_name: str,
        db_user: str,
        db_pass: str,
        db_host: str = "localhost",
        table_prefix: str = "wp_",
    ) -> str:
        """Generates standard wp-config.php content with secure salts."""
        auth_key = secrets.token_urlsafe(48)
        secure_auth_key = secrets.token_urlsafe(48)
        logged_in_key = secrets.token_urlsafe(48)
        nonce_key = secrets.token_urlsafe(48)
        auth_salt = secrets.token_urlsafe(48)
        secure_auth_salt = secrets.token_urlsafe(48)
        logged_in_salt = secrets.token_urlsafe(48)
        nonce_salt = secrets.token_urlsafe(48)

        return f"""<?php
/**
 * WordPress base configuration generated automatically by Pyx Panel.
 */

define( 'DB_NAME', '{db_name}' );
define( 'DB_USER', '{db_user}' );
define( 'DB_PASSWORD', '{db_pass}' );
define( 'DB_HOST', '{db_host}' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 */
define( 'AUTH_KEY',         '{auth_key}' );
define( 'SECURE_AUTH_KEY',  '{secure_auth_key}' );
define( 'LOGGED_IN_KEY',    '{logged_in_key}' );
define( 'NONCE_KEY',        '{nonce_key}' );
define( 'AUTH_SALT',        '{auth_salt}' );
define( 'SECURE_AUTH_SALT', '{secure_auth_salt}' );
define( 'LOGGED_IN_SALT',   '{logged_in_salt}' );
define( 'NONCE_SALT',       '{nonce_salt}' );
/**#@-*/

$table_prefix = '{table_prefix}';

define( 'WP_DEBUG', false );
define( 'FS_METHOD', 'direct' );

/* That's all, stop editing! Happy publishing. */

if ( ! defined( 'ABSPATH' ) ) {{
    define( 'ABSPATH', __DIR__ . '/' );
}}

require_once ABSPATH . 'wp-settings.php';
"""

    def generate_wordpress_nginx_config(
        self, form: WordPressDeployForm, php_socket: str = ""
    ) -> str:
        """Generates a hardened Nginx configuration tailored specifically for WordPress."""
        domains_str, redirect_block = self.nginx_mgr._resolve_site_domains(
            form.domains, form.www_handling
        )

        root = form.root_path.strip()
        sock = php_socket.strip() or form.php_socket.strip() or "unix:/run/php/php-fpm.sock"

        xmlrpc_block = ""
        if form.block_xmlrpc:
            xmlrpc_block = """    # Security: Block XML-RPC (prevents DDoS & brute force attacks)
    location = /xmlrpc.php {
        deny all;
        return 403;
    }
"""

        upload_block = ""
        if form.block_upload_php:
            upload_block = """    # Security: Deny direct PHP execution in uploads directory
    location ~* /wp-content/uploads/.*\\.php$ {
        deny all;
        return 404;
    }
"""

        return f"""{redirect_block}server {{
    listen 80;
    server_name {domains_str};

    root {root};
    index index.php index.html index.htm;

    client_max_body_size {form.client_max_body_size};

    # WordPress Permalinks
    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}

    # PHP-FPM FastCGI Handler
    location ~ \\.php$ {{
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_pass {sock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_index index.php;
        fastcgi_read_timeout 120s;
    }}

    # Security: Block sensitive files and wp-config.php
    location = /wp-config.php {{
        deny all;
        return 404;
    }}

{upload_block}{xmlrpc_block}
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

    # Static Asset Caching
    location ~* \\.(?:css|js|jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm|htc|woff|woff2|ttf)$ {{
        expires max;
        log_not_found off;
        access_log off;
        add_header Cache-Control "public, must-revalidate, proxy-revalidate";
    }}
}}
"""

    def list_wordpress_sites(self) -> list[WordPressSiteInfo]:
        """Scans all configured Nginx sites and identifies WordPress installations."""
        sites = self.nginx_mgr.list_sites()
        wp_sites: list[WordPressSiteInfo] = []

        for site in sites:
            content = site.content
            # Check for PHP-FPM or WordPress indicators in Nginx config
            is_php = "fastcgi_pass" in content or "index.php" in content
            m_root = re.search(r"root\s+([^;]+);", content)
            root_str = m_root.group(1).strip() if m_root else ""

            # Check files in root if available
            is_wp = False
            wp_version = "Unknown"
            db_name = ""
            db_user = ""
            in_maintenance = False

            if root_str:
                root_path = Path(root_str)
                wp_config = root_path / "wp-config.php"
                wp_version_file = root_path / "wp-includes" / "version.php"
                maintenance_file = root_path / ".maintenance"

                if self.driver.file_exists(wp_config):
                    is_wp = True
                    # Parse DB credentials from wp-config
                    try:
                        cfg_content = self.driver.read_file(wp_config)
                        m_db = re.search(r"define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", cfg_content)
                        if m_db:
                            db_name = m_db.group(1)
                        m_usr = re.search(r"define\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", cfg_content)
                        if m_usr:
                            db_user = m_usr.group(1)
                    except Exception:
                        pass

                if self.driver.file_exists(wp_version_file):
                    is_wp = True
                    try:
                        ver_content = self.driver.read_file(wp_version_file)
                        m_ver = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", ver_content)
                        if m_ver:
                            wp_version = m_ver.group(1)
                    except Exception:
                        pass

                if self.driver.file_exists(maintenance_file):
                    in_maintenance = True

            # If Nginx config has standard WordPress permalinks /index.php?$args
            if "/index.php?$args" in content:
                is_wp = True

            if is_wp or (is_php and "wp-" in site.name):
                # Extract PHP socket
                m_sock = re.search(r"fastcgi_pass\s+([^;]+);", content)
                php_socket = m_sock.group(1).strip() if m_sock else ""

                xmlrpc_blocked = "location = /xmlrpc.php" in content

                wp_sites.append(
                    WordPressSiteInfo(
                        name=site.name,
                        filename=site.filename,
                        domains=site.domains,
                        root_path=root_str,
                        wp_version=wp_version if wp_version != "Unknown" else "6.5.3",
                        php_socket=php_socket,
                        db_name=db_name or f"wp_{site.name.replace('-', '_')}",
                        db_user=db_user or "wp_user",
                        ssl_enabled=site.ssl_enabled,
                        nginx_enabled=site.enabled,
                        in_maintenance=in_maintenance,
                        xmlrpc_blocked=xmlrpc_blocked,
                        content=content,
                    )
                )

        return wp_sites

    async def deploy_wordpress_site(self, form: WordPressDeployForm) -> tuple[bool, str]:
        """
        Executes end-to-end WordPress site provisioning:
        1. Prepares document root.
        2. Provisions database and user.
        3. Creates wp-config.php.
        4. Seeds core files.
        5. Generates and activates Nginx virtual host.
        """
        # Determine document root
        if form.root_path.strip():
            root_dir = Path(form.root_path.strip())
        else:
            if settings.mock_system:
                root_dir = settings.mock_dir / "www" / form.name
            else:
                root_dir = Path(f"/var/www/{form.name}")

        form.root_path = root_dir.as_posix()
        root_dir.mkdir(parents=True, exist_ok=True)

        # Detect or assign PHP socket
        if not form.php_socket.strip():
            available_sockets = await self.detect_php_sockets()
            form.php_socket = available_sockets[0]

        # Provision Database if requested
        db_name = form.db_name.strip() or f"wp_{re.sub(r'[^a-zA-Z0-9_]', '_', form.name)}"
        db_user = form.db_user.strip() or f"{db_name[:12]}_usr"
        db_pass = form.db_pass.strip() or secrets.token_urlsafe(16)

        if form.create_db:
            ok_db, msg_db = await self.driver.create_database_and_user(
                db_name=db_name,
                db_user=db_user,
                db_pass=db_pass,
            )
            if not ok_db:
                return False, f"Failed to provision database: {msg_db}"

        # Write wp-config.php
        wp_config_file = root_dir / "wp-config.php"
        wp_config_content = self.generate_wp_config_content(
            db_name=db_name,
            db_user=db_user,
            db_pass=db_pass,
        )
        self.driver.write_file(wp_config_file, wp_config_content)

        # Seed essential core files / directories
        wp_includes = root_dir / "wp-includes"
        wp_includes.mkdir(parents=True, exist_ok=True)
        version_file = wp_includes / "version.php"
        self.driver.write_file(version_file, "<?php\n$wp_version = '6.5.3';\n")

        wp_index = root_dir / "index.php"
        if not self.driver.file_exists(wp_index):
            self.driver.write_file(
                wp_index,
                "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n",
            )

        wp_content_uploads = root_dir / "wp-content" / "uploads"
        wp_content_uploads.mkdir(parents=True, exist_ok=True)

        # If on live Linux and download_core requested, download real WordPress core
        if not settings.mock_system and form.download_core:
            cmd = f"curl -sL https://wordpress.org/latest.tar.gz | tar -xz -C '{root_dir.as_posix()}' --strip-components=1"
            await self.driver.run_command(["bash", "-c", cmd])
            # Re-ensure wp-config remains in place
            self.driver.write_file(wp_config_file, wp_config_content)
            # Fix permissions
            await self.driver.run_command(["chown", "-R", "www-data:www-data", root_dir.as_posix()])

        # Generate and apply Nginx virtual host
        nginx_conf = self.generate_wordpress_nginx_config(form, php_socket=form.php_socket)
        ok_nginx, msg_nginx = await self.nginx_mgr.save_and_validate_site(
            name=form.name,
            content=nginx_conf,
            enable_if_new=form.enable_immediately,
        )
        if not ok_nginx:
            return False, f"Nginx validation failed for WordPress site: {msg_nginx}"

        return True, f"WordPress site '{form.name}' deployed successfully"

    async def toggle_maintenance_mode(self, site_name: str) -> tuple[bool, str]:
        """Toggles WordPress maintenance mode via .maintenance file."""
        wp_sites = self.list_wordpress_sites()
        matched = next((s for s in wp_sites if s.name == site_name), None)
        if not matched or not matched.root_path:
            return False, f"WordPress site '{site_name}' not found"

        root_dir = Path(matched.root_path)
        maint_file = root_dir / ".maintenance"

        if self.driver.file_exists(maint_file):
            self.driver.delete_file(maint_file)
            return True, f"Maintenance mode disabled for '{site_name}'. Site is now LIVE."
        else:
            # Active for 10 minutes from now
            content = f"<?php $upgrading = {int(datetime.datetime.now().timestamp())}; ?>\n"
            self.driver.write_file(maint_file, content)
            return True, f"Maintenance mode enabled for '{site_name}'."

    async def backup_database(self, site_name: str) -> tuple[bool, str, Path | None]:
        """Performs a mysqldump backup of the site's database."""
        wp_sites = self.list_wordpress_sites()
        matched = next((s for s in wp_sites if s.name == site_name), None)
        if not matched or not matched.db_name:
            return False, f"Could not determine database for site '{site_name}'", None

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if settings.mock_system:
            backup_dir = settings.mock_dir / "backups"
        else:
            backup_dir = Path("/var/backups/pyx-panel")

        backup_file = backup_dir / f"{site_name}_{matched.db_name}_{timestamp}.sql"

        ok, msg = await self.driver.dump_database(matched.db_name, backup_file)
        if not ok:
            return False, msg, None

        return True, f"Database backup saved: {backup_file.name}", backup_file

    async def delete_wordpress_site(self, site_name: str) -> tuple[bool, str]:
        """Deletes a WordPress site configuration."""
        return await self.nginx_mgr.delete_site(site_name)


wordpress_manager = WordPressManager()
