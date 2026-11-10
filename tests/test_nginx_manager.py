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


def test_parse_domain_and_www_alias():
    from pyx_panel.services.nginx_manager import parse_domain_and_www_alias
    assert parse_domain_and_www_alias("example.com") == ("example.com", "www.example.com")
    assert parse_domain_and_www_alias("www.example.com") == ("example.com", "www.example.com")
    assert parse_domain_and_www_alias("localhost") == ("localhost", None)
    assert parse_domain_and_www_alias("127.0.0.1") == ("127.0.0.1", None)
    assert parse_domain_and_www_alias("my.sub.domain.com") == ("my.sub.domain.com", "www.my.sub.domain.com")


def test_generate_reverse_proxy_with_www_as_main_domain(manager):
    form = ReverseProxyForm(
        name="go-api",
        domains="example.com",
        upstream="http://127.0.0.1:8080",
        www_handling="redirect_to_www",
    )
    conf = manager.generate_reverse_proxy_config(form)
    assert "server_name example.com;" in conf
    assert "return 301 $scheme://www.example.com$request_uri;" in conf
    assert "server_name www.example.com;" in conf
    assert "proxy_pass http://127.0.0.1:8080;" in conf


def test_generate_reverse_proxy_with_root_as_main_domain(manager):
    form = ReverseProxyForm(
        name="go-api",
        domains="www.example.com",
        upstream="http://127.0.0.1:8080",
        www_handling="redirect_to_root",
    )
    conf = manager.generate_reverse_proxy_config(form)
    assert "server_name www.example.com;" in conf
    assert "return 301 $scheme://example.com$request_uri;" in conf
    assert "server_name example.com;" in conf
    assert "proxy_pass http://127.0.0.1:8080;" in conf


def test_generate_reverse_proxy_with_both_domains(manager):
    form = ReverseProxyForm(
        name="go-api",
        domains="example.com",
        upstream="http://127.0.0.1:8080",
        www_handling="both",
    )
    conf = manager.generate_reverse_proxy_config(form)
    assert "return 301" not in conf
    assert "server_name example.com www.example.com;" in conf


def test_generate_static_with_www_as_main_domain(manager):
    form = StaticSiteForm(
        name="web-site",
        domains="example.com",
        root_path="/var/www/web",
        www_handling="redirect_to_www",
    )
    conf = manager.generate_static_config(form)
    assert "server_name example.com;" in conf
    assert "return 301 $scheme://www.example.com$request_uri;" in conf
    assert "server_name www.example.com;" in conf
    assert "root /var/www/web;" in conf


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


def test_remove_ssl_from_config_certbot_split_blocks(manager):
    certbot_conf = """server {
    server_name example.com www.example.com;
    root /var/www/example;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}
server {
    if ($host = www.example.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


    if ($host = example.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


    listen 80;
    server_name example.com www.example.com;
    return 404; # managed by Certbot
}
"""
    cleaned = manager.remove_ssl_from_config(certbot_conf)

    # Certbot redirect block and if statements should be removed
    assert "return 301 https:" not in cleaned
    assert "return 404" not in cleaned
    assert "managed by Certbot" not in cleaned

    # SSL directives should be removed
    assert "ssl_certificate" not in cleaned
    assert "options-ssl-nginx.conf" not in cleaned
    assert "443" not in cleaned

    # Server block must now listen on port 80
    assert "listen 80;" in cleaned
    assert "server_name example.com www.example.com;" in cleaned
    assert "root /var/www/example;" in cleaned


def test_remove_ssl_from_config_combined_blocks(manager):
    combined_conf = """server {
    listen 80;
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name myapi.io;
    ssl_certificate /etc/letsencrypt/live/myapi.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/myapi.io/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
"""
    cleaned = manager.remove_ssl_from_config(combined_conf)
    assert "listen 80;" in cleaned
    assert "443" not in cleaned
    assert "ssl_certificate" not in cleaned
    assert "proxy_pass http://127.0.0.1:3000;" in cleaned


@pytest.mark.asyncio
async def test_remove_ssl_from_site_lifecycle(manager):
    site_name = "test-ssl-revert"
    conf = """server {
    listen 80;
    listen 443 ssl;
    server_name revert.example.com;
    ssl_certificate /etc/letsencrypt/live/revert.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/revert.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
"""
    saved, _ = await manager.save_and_validate_site(site_name, conf, enable_if_new=True)
    assert saved is True

    site_before = manager.get_site(site_name)
    assert site_before is not None
    assert site_before.ssl_enabled is True

    # Revert to HTTP
    ok, msg = await manager.remove_ssl_from_site(site_name)
    assert ok is True
    assert "SSL removed" in msg

    site_after = manager.get_site(site_name)
    assert site_after is not None
    assert site_after.ssl_enabled is False
    assert "listen 80;" in site_after.content
    assert "ssl_certificate" not in site_after.content

    # Clean up
    await manager.delete_site(site_name)



