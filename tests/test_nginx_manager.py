"""Unit tests for Nginx configuration manager."""
import pytest
from pyx_panel.services.nginx_manager import (
    NginxManager,
    ReverseProxyForm,
    StaticSiteForm,
)


@pytest.fixture
def manager():
    mgr = NginxManager()
    for d in (mgr.available_dir, mgr.enabled_dir):
        p = d / "default-deny.conf"
        if mgr.driver.file_exists(p):
            mgr.driver.delete_file(p)
    yield mgr
    for d in (mgr.available_dir, mgr.enabled_dir):
        p = d / "default-deny.conf"
        if mgr.driver.file_exists(p):
            mgr.driver.delete_file(p)


def test_generate_reverse_proxy_config(manager):
    form = ReverseProxyForm(
        name="go-api",
        domains="api.example.com",
        upstream="http://127.0.0.1:8080",
        enable_websocket=True,
        client_max_body_size="100M",
    )
    conf = manager.generate_reverse_proxy_config(form)
    assert "server_name api.example.com;" in conf
    assert "proxy_pass http://127.0.0.1:8080;" in conf
    assert "proxy_set_header Upgrade $http_upgrade;" in conf
    assert "client_max_body_size 100M;" in conf


def test_generate_static_config(manager):
    form = StaticSiteForm(
        name="web-site",
        domains="web.example.com",
        root_path="/var/www/web",
        spa_fallback=True,
    )
    conf = manager.generate_static_config(form)
    assert "server_name web.example.com;" in conf
    assert "root /var/www/web;" in conf
    assert "try_files $uri $uri/ /index.html;" in conf


@pytest.mark.asyncio
async def test_save_and_revert_invalid_syntax(manager):
    # Test valid syntax save
    valid_conf = """server {
    listen 80;
    server_name test.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
"""
    success, msg = await manager.save_and_validate_site("test-valid", valid_conf)
    assert success is True

    # Test invalid syntax (unclosed brace) -> should fail and revert
    invalid_conf = """server {
    listen 80;
    server_name broken.example.com;
"""
    success_broken, msg_broken = await manager.save_and_validate_site("test-broken", invalid_conf)
    assert success_broken is False
    assert "validation failed" in msg_broken.lower() or "syntax" in msg_broken.lower()

    # Clean up
    await manager.delete_site("test-valid")


@pytest.mark.asyncio
async def test_enable_site_copies_to_sites_enabled(manager):
    test_conf = "server { listen 80; server_name copy-test.example.com; }"
    await manager.save_and_validate_site("copy-test", test_conf, enable_if_new=False)

    avail_path = manager.available_dir / "copy-test.conf"
    enabled_path = manager.enabled_dir / "copy-test.conf"

    # Initially not enabled
    assert manager.driver.file_exists(avail_path) is True
    assert manager.driver.file_exists(enabled_path) is False

    # Enable site -> copies to sites-enabled
    ok_en, _ = await manager.enable_site("copy-test")
    assert ok_en is True
    assert manager.driver.file_exists(enabled_path) is True
    assert manager.driver.read_file(enabled_path) == test_conf

    # Disable site -> removes from sites-enabled
    ok_dis, _ = await manager.disable_site("copy-test")
    assert ok_dis is True
    assert manager.driver.file_exists(enabled_path) is False

    # Cleanup
    await manager.delete_site("copy-test")


def test_list_sites_ignores_default(manager):
    # Simulate a 'default' site existing on disk
    default_path = manager.available_dir / "default"
    manager.driver.write_file(default_path, "server { listen 80; server_name _; }")
    try:
        sites = manager.list_sites()
        assert not any(s.name == "default" or s.filename == "default" for s in sites)
    finally:
        manager.driver.delete_file(default_path)


@pytest.mark.asyncio
async def test_nginx_default_deny_lifecycle(manager):
    assert manager.is_default_deny_active() is False

    # Enable default deny catch-all
    ok, msg = await manager.enable_default_deny()
    assert ok is True
    assert manager.is_default_deny_active() is True

    # Verify default-deny.conf is in sites-enabled and contains return 444
    enabled_conf = manager.driver.read_file(manager.enabled_dir / "default-deny.conf")
    assert "return 444;" in enabled_conf
    assert "ssl_reject_handshake on;" in enabled_conf

    # Verify default-deny is NOT shown in normal list_sites()
    sites = manager.list_sites()
    assert not any("default-deny" in s.name for s in sites)

    # Disable default deny
    dis_ok, dis_msg = await manager.disable_default_deny()
    assert dis_ok is True
    assert manager.is_default_deny_active() is False

    # Clean up
    await manager.delete_site("default-deny")


@pytest.mark.asyncio
async def test_nginx_default_deny_handles_ubuntu_default_site(manager):
    # Simulate Ubuntu's boilerplate default site in sites-enabled
    ubuntu_default = manager.enabled_dir / "default"
    manager.driver.write_file(ubuntu_default, "server { listen 80 default_server; server_name _; }")
    assert manager.driver.file_exists(ubuntu_default) is True

    # Enabling default deny should automatically displace Ubuntu's boilerplate default
    ok, msg = await manager.enable_default_deny()
    assert ok is True
    assert manager.is_default_deny_active() is True
    # The conflicting Ubuntu default should have been removed from sites-enabled
    assert manager.driver.file_exists(ubuntu_default) is False

    # Clean up
    await manager.disable_default_deny()
    await manager.delete_site("default-deny")


@pytest.mark.asyncio
async def test_nginx_default_deny_blocks_on_custom_site_conflict(manager):
    # Simulate a user's custom site having default_server
    custom_conf = manager.enabled_dir / "my-custom.conf"
    manager.driver.write_file(custom_conf, "server { listen 80 default_server; server_name custom.com; }")

    try:
        ok, err = await manager.enable_default_deny()
        assert ok is False
        assert "my-custom.conf" in err
        assert "Conflicting 'default_server'" in err
    finally:
        manager.driver.delete_file(custom_conf)


