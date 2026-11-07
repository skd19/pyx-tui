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


def test_normalize_domain_list(cert_mgr):
    assert cert_mgr.normalize_domain_list("example.com") == ["example.com"]
    assert cert_mgr.normalize_domain_list("example.com", include_www=True) == ["example.com", "www.example.com"]
    assert cert_mgr.normalize_domain_list("www.example.com", include_www=True) == ["example.com", "www.example.com"]
    assert cert_mgr.normalize_domain_list("example.com, blog.example.com") == ["example.com", "blog.example.com"]
    assert cert_mgr.normalize_domain_list("localhost", include_www=True) == ["localhost"]


@pytest.mark.asyncio
async def test_check_domain_dns_multi_domain(cert_mgr):
    res = await cert_mgr.check_domain_dns(["localhost", "127.0.0.1"])
    assert res.domain == "localhost, 127.0.0.1"
    assert "127.0.0.1" in res.domain_ips
    assert "localhost" in res.details
    assert "127.0.0.1" in res.details


@pytest.mark.asyncio
async def test_provision_certificate_with_www_alias(cert_mgr):
    success, msg = await cert_mgr.provision_certificate(
        domain="example.com",
        email="admin@example.com",
        force=True,
        include_www=True,
    )
    assert success
    assert "example.com" in msg
    assert "www.example.com" in msg

    certs = await cert_mgr.list_certificates()
    assert any("example.com" in c["domains"] and "www.example.com" in c["domains"] for c in certs)
