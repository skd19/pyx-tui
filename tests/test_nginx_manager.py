"""Unit tests for Nginx configuration manager."""
import pytest
from pyx_panel.services.nginx_manager import (
    NginxManager,
    ReverseProxyForm,
    StaticSiteForm,
)


@pytest.fixture
def manager():
    return NginxManager()


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
