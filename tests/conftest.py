"""Shared pytest fixtures for pyx-panel test suite."""
import pytest
from starlette.testclient import TestClient

from pyx_panel.config import settings
from pyx_panel.main import app
from pyx_panel.web.auth import COOKIE_NAME, create_session_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_client():
    from pyx_panel.services.nginx_manager import nginx_manager
    for d in (nginx_manager.available_dir, nginx_manager.enabled_dir):
        p = d / "default-deny.conf"
        if nginx_manager.driver.file_exists(p):
            nginx_manager.driver.delete_file(p)
    if nginx_manager.is_security_guard_active():
        nginx_manager.driver.delete_file(nginx_manager.conf_d_dir / "pyx-security-guard.conf")

    c = TestClient(app)
    token = settings.get_token()
    cookie_val = create_session_token(token)
    c.cookies.set(COOKIE_NAME, cookie_val)
    yield c

    for d in (nginx_manager.available_dir, nginx_manager.enabled_dir):
        p = d / "default-deny.conf"
        if nginx_manager.driver.file_exists(p):
            nginx_manager.driver.delete_file(p)
    if nginx_manager.is_security_guard_active():
        nginx_manager.driver.delete_file(nginx_manager.conf_d_dir / "pyx-security-guard.conf")
