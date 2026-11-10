"""Unit and integration tests for WordPress management in pyx-panel."""
import asyncio
from pathlib import Path
import pytest
from pyx_panel.config import settings
from pyx_panel.services.package_manager import DEFAULT_PACKAGE_CATALOG, package_manager
from pyx_panel.services.wordpress_manager import (
    WordPressDeployForm,
    WordPressManager,
    wordpress_manager,
)


@pytest.fixture
def wp_mgr():
    mgr = WordPressManager()
    yield mgr
    # Cleanup any mock sites
    for site in mgr.list_wordpress_sites():
        if site.name.startswith("test-"):
            asyncio.run(mgr.delete_wordpress_site(site.name))


@pytest.mark.asyncio
async def test_detect_php_sockets(wp_mgr):
    sockets = await wp_mgr.detect_php_sockets()
    assert len(sockets) > 0
    assert any("php" in s for s in sockets)


def test_generate_wp_config_content(wp_mgr):
    content = wp_mgr.generate_wp_config_content(
        db_name="wp_myblog",
        db_user="wp_user",
        db_pass="secret123",
        db_host="127.0.0.1",
        table_prefix="wp_",
    )
    assert "define( 'DB_NAME', 'wp_myblog' );" in content
    assert "define( 'DB_USER', 'wp_user' );" in content
    assert "define( 'DB_PASSWORD', 'secret123' );" in content
    assert "define( 'AUTH_KEY'," in content
    assert "$table_prefix = 'wp_';" in content
    assert "define( 'FS_METHOD', 'direct' );" in content


def test_generate_wordpress_nginx_config(wp_mgr):
    form = WordPressDeployForm(
        name="test-blog",
        domains="example.com",
        www_handling="redirect_to_www",
        root_path="/var/www/test-blog",
        php_socket="unix:/run/php/php8.2-fpm.sock",
        block_xmlrpc=True,
        block_upload_php=True,
        client_max_body_size="100M",
    )
    conf = wp_mgr.generate_wordpress_nginx_config(form)

    # Check permalinks
    assert "try_files $uri $uri/ /index.php?$args;" in conf
    # Check FastCGI
    assert "fastcgi_pass unix:/run/php/php8.2-fpm.sock;" in conf
    assert "fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;" in conf
    # Check security blocks
    assert "location = /wp-config.php" in conf
    assert "location = /xmlrpc.php" in conf
    assert "/wp-content/uploads/" in conf
    # Check canonical www redirect
    assert "server_name example.com;" in conf
    assert "return 301 $scheme://www.example.com$request_uri;" in conf
    assert "client_max_body_size 100M;" in conf


@pytest.mark.asyncio
async def test_deploy_wordpress_site(wp_mgr):
    form = WordPressDeployForm(
        name="test-wp-site",
        domains="wp.example.com",
        www_handling="none",
        create_db=True,
        db_name="wp_test_db",
        db_user="wp_test_usr",
        db_pass="pass_secret",
        block_xmlrpc=True,
        block_upload_php=True,
        enable_immediately=True,
    )

    success, msg = await wp_mgr.deploy_wordpress_site(form)
    assert success
    assert "deployed successfully" in msg

    # Verify site appears in list_wordpress_sites
    sites = wp_mgr.list_wordpress_sites()
    matched = next((s for s in sites if s.name == "test-wp-site"), None)
    assert matched is not None
    assert matched.db_name == "wp_test_db"
    assert "wp.example.com" in matched.domains
    assert not matched.in_maintenance

    # Verify files created in mock dir
    root_p = Path(matched.root_path)
    assert wp_mgr.driver.file_exists(root_p / "wp-config.php")
    assert wp_mgr.driver.file_exists(root_p / "wp-includes" / "version.php")


@pytest.mark.asyncio
async def test_toggle_maintenance_mode(wp_mgr):
    form = WordPressDeployForm(
        name="test-maint-site",
        domains="maint.example.com",
        create_db=True,
    )
    ok, _ = await wp_mgr.deploy_wordpress_site(form)
    assert ok

    # Activate maintenance
    ok_act, msg_act = await wp_mgr.toggle_maintenance_mode("test-maint-site")
    assert ok_act
    assert "Maintenance mode enabled" in msg_act

    sites = wp_mgr.list_wordpress_sites()
    matched = next(s for s in sites if s.name == "test-maint-site")
    assert matched.in_maintenance is True

    # Deactivate maintenance
    ok_deact, msg_deact = await wp_mgr.toggle_maintenance_mode("test-maint-site")
    assert ok_deact
    assert "disabled" in msg_deact.lower() or "live" in msg_deact.lower()

    sites2 = wp_mgr.list_wordpress_sites()
    matched2 = next(s for s in sites2 if s.name == "test-maint-site")
    assert matched2.in_maintenance is False


@pytest.mark.asyncio
async def test_backup_database(wp_mgr):
    form = WordPressDeployForm(
        name="test-backup-site",
        domains="backup.example.com",
        create_db=True,
        db_name="wp_backup_db",
    )
    ok, _ = await wp_mgr.deploy_wordpress_site(form)
    assert ok

    ok_bk, msg_bk, path_bk = await wp_mgr.backup_database("test-backup-site")
    assert ok_bk
    assert path_bk is not None
    assert path_bk.name.endswith(".sql")
    assert path_bk.exists()
    assert "wp_options" in path_bk.read_text(encoding="utf-8")


def test_package_catalog_contains_wordpress_prerequisites():
    ids = [p["id"] for p in DEFAULT_PACKAGE_CATALOG]
    assert "php-fpm" in ids
    assert "mariadb-server" in ids
    assert "wp-cli" in ids


def test_wordpress_web_endpoints(auth_client):
    # 1. View WordPress dashboard
    res = auth_client.get("/wordpress")
    assert res.status_code == 200
    assert "WordPress Manager" in res.text
    assert "PHP-FPM Engine" in res.text
    assert "Database Server" in res.text

    # 2. Deploy WordPress site via POST
    res_new = auth_client.post(
        "/wordpress/new",
        data={
            "name": "e2e-wp-site",
            "domains": "e2ewp.com",
            "www_handling": "redirect_to_www",
            "create_db": "true",
            "db_name": "wp_e2e_db",
            "db_user": "wp_e2e_usr",
            "db_pass": "pass_123",
            "block_xmlrpc": "true",
            "block_upload_php": "true",
            "client_max_body_size": "64M",
            "enable_immediately": "true",
        },
        follow_redirects=True,
    )
    assert res_new.status_code == 200
    assert "e2e-wp-site" in res_new.text

    # 3. Toggle Maintenance Mode
    res_maint = auth_client.post("/wordpress/e2e-wp-site/maintenance", follow_redirects=True)
    assert res_maint.status_code == 200
    assert "Maintenance mode" in res_maint.text

    # 4. Backup Database
    res_backup = auth_client.post("/wordpress/e2e-wp-site/backup", follow_redirects=True)
    assert res_backup.status_code == 200
    assert "Database backup saved" in res_backup.text

    # 5. Delete Site
    res_del = auth_client.post("/wordpress/e2e-wp-site/delete", follow_redirects=True)
    assert res_del.status_code == 200
    assert "deleted successfully" in res_del.text
