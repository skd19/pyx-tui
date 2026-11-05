"""Unit tests for VPS Security Manager and Threat Hardening."""
import pytest
from pyx_panel.core.mock_driver import MockSystemDriver
from pyx_panel.services.nginx_manager import nginx_manager
from pyx_panel.services.security_manager import SecurityManager


@pytest.fixture
def sec_manager():
    mgr = SecurityManager()
    # Reset mock state
    if isinstance(mgr.driver, MockSystemDriver):
        mgr.driver.mock_has_authorized_keys = True
        mgr.driver.mock_ssh_config = {
            "port": 22,
            "password_authentication": True,
            "permit_root_login": "yes",
        }
    for d in (mgr.nginx_mgr.available_dir, mgr.nginx_mgr.enabled_dir):
        p = d / "default-deny.conf"
        if mgr.driver.file_exists(p):
            mgr.driver.delete_file(p)
    if mgr.nginx_mgr.is_security_guard_active():
        target = mgr.nginx_mgr.conf_d_dir / "pyx-security-guard.conf"
        mgr.driver.delete_file(target)

    yield mgr

    for d in (mgr.nginx_mgr.available_dir, mgr.nginx_mgr.enabled_dir):
        p = d / "default-deny.conf"
        if mgr.driver.file_exists(p):
            mgr.driver.delete_file(p)
    if mgr.nginx_mgr.is_security_guard_active():
        target = mgr.nginx_mgr.conf_d_dir / "pyx-security-guard.conf"
        mgr.driver.delete_file(target)


@pytest.mark.asyncio
async def test_run_security_audit(sec_manager):
    report = await sec_manager.run_security_audit()
    assert 0 <= report.score <= 100
    assert report.score_grade in ("A+", "A", "B", "C", "F")
    assert report.stats["total"] > 0
    assert len(report.checks) == report.stats["total"]
    assert any(c.id == "ufw_status" for c in report.checks)
    assert any(c.id == "ssh_password_auth" for c in report.checks)
    assert any(c.id == "direct_ip_drop" for c in report.checks)
    assert any(c.id == "nginx_security_guard" for c in report.checks)
    assert len(report.listening_ports) > 0


@pytest.mark.asyncio
async def test_ssh_keys_only_safety_check(sec_manager):
    # Disable authorized keys in mock driver
    if isinstance(sec_manager.driver, MockSystemDriver):
        sec_manager.driver.mock_has_authorized_keys = False

    ok, msg = await sec_manager.harden_ssh_keys_only()
    assert not ok
    assert "Anti-Lockout Protection" in msg

    # Restore authorized keys
    if isinstance(sec_manager.driver, MockSystemDriver):
        sec_manager.driver.mock_has_authorized_keys = True

    ok, msg = await sec_manager.harden_ssh_keys_only()
    assert ok
    assert "hardened" in msg.lower()
    assert not sec_manager.driver.mock_ssh_config["password_authentication"]


@pytest.mark.asyncio
async def test_restrict_ssh_root(sec_manager):
    ok, msg = await sec_manager.restrict_ssh_root()
    assert ok
    assert "prohibit-password" in sec_manager.driver.mock_ssh_config["permit_root_login"]


@pytest.mark.asyncio
async def test_apply_kernel_hardening(sec_manager):
    ok, msg = await sec_manager.apply_kernel_hardening()
    assert ok
    syn = await sec_manager.driver.read_sysctl_setting("net.ipv4.tcp_syncookies")
    assert syn == "1"


@pytest.mark.asyncio
async def test_isolate_port_ufw(sec_manager):
    ok, msg = await sec_manager.isolate_port_ufw("8080", proto="tcp")
    assert ok
    status = await sec_manager.ufw_mgr.get_status()
    has_deny = any(r.port in ("8080", "8080/tcp") and "DENY" in r.action for r in status.rules)
    assert has_deny


@pytest.mark.asyncio
async def test_nginx_security_guard_lifecycle(sec_manager):
    # Initially inactive or clear
    if sec_manager.nginx_mgr.is_security_guard_active():
        await sec_manager.nginx_mgr.revert_security_guard()
    assert not sec_manager.nginx_mgr.is_security_guard_active()

    # Enable guard
    ok, msg = await sec_manager.nginx_mgr.apply_security_guard()
    assert ok
    assert sec_manager.nginx_mgr.is_security_guard_active()

    # Disable guard
    ok, msg = await sec_manager.nginx_mgr.revert_security_guard()
    assert ok
    assert not sec_manager.nginx_mgr.is_security_guard_active()


@pytest.mark.asyncio
async def test_harden_all(sec_manager):
    results = await sec_manager.harden_all()
    assert "ufw" in results
    assert "nginx_guard" in results
    assert "direct_ip_drop" in results
    assert "kernel" in results
    assert "ssh" in results
    assert results["ufw"][0]
    assert results["nginx_guard"][0]
    assert results["direct_ip_drop"][0]
    assert results["kernel"][0]
    assert results["ssh"][0]
