"""Unit tests for Certbot manager and DNS verification."""
import pytest
from pyx_panel.services.certbot_manager import CertbotManager


@pytest.fixture
def cert_mgr():
    return CertbotManager()


@pytest.mark.asyncio
async def test_get_public_ip(cert_mgr):
    ip = await cert_mgr.get_public_ip()
    assert ip != ""
    assert isinstance(ip, str)


@pytest.mark.asyncio
async def test_check_domain_dns_localhost(cert_mgr):
    # In mock mode or local testing, localhost should resolve
    res = await cert_mgr.check_domain_dns("localhost")
    assert res.domain == "localhost"
    assert "127.0.0.1" in res.domain_ips
