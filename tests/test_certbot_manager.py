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


@pytest.mark.asyncio
async def test_remove_certificate(cert_mgr):
    # Provision
    success, _ = await cert_mgr.provision_certificate(
        domain="sample.com",
        email="admin@sample.com",
        force=True,
    )
    assert success is True
    certs = await cert_mgr.list_certificates()
    assert any("sample.com" in c["domains"] for c in certs)

    # Remove
    del_ok, del_msg = await cert_mgr.remove_certificate("sample.com")
    assert del_ok is True
    assert "removed successfully" in del_msg

    # Verify cert is gone
    certs_after = await cert_mgr.list_certificates()
    assert not any("sample.com" in c.get("domains", []) for c in certs_after)


@pytest.mark.asyncio
async def test_remove_certificate_with_associated_site(cert_mgr):
    from pyx_panel.services.nginx_manager import ReverseProxyForm, nginx_manager

    # 1. Create site
    form = ReverseProxyForm(
        name="test-cert-site",
        domains="mysecuresite.org",
        upstream="http://127.0.0.1:9000",
        enable_immediately=True,
    )
    conf = nginx_manager.generate_reverse_proxy_config(form)
    await nginx_manager.save_and_validate_site("test-cert-site", conf, enable_if_new=True)

    # 2. Provision certificate
    ok, _ = await cert_mgr.provision_certificate(
        domain="mysecuresite.org",
        force=True,
    )
    assert ok is True

    site_sec = nginx_manager.get_site("test-cert-site")
    assert site_sec is not None
    assert site_sec.ssl_enabled is True

    # 3. Remove certificate
    rem_ok, rem_msg = await cert_mgr.remove_certificate("mysecuresite.org")
    assert rem_ok is True

    # 4. Site should now be reverted to HTTP
    site_reverted = nginx_manager.get_site("test-cert-site")
    assert site_reverted is not None
    assert site_reverted.ssl_enabled is False
    assert "listen 80;" in site_reverted.content

    # Clean up
    await nginx_manager.delete_site("test-cert-site")

