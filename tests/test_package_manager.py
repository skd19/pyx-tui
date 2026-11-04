"""Unit tests for package manager and prerequisite tracking."""
import pytest
from pyx_panel.services.package_manager import package_manager


@pytest.mark.asyncio
async def test_package_catalog_inspection():
    packages = await package_manager.get_packages()
    assert len(packages) >= 8

    pkg_ids = [p.id for p in packages]
    assert "nginx" in pkg_ids
    assert "ufw" in pkg_ids
    assert "certbot" in pkg_ids
    assert "python3-certbot-nginx" in pkg_ids
    assert "curl" in pkg_ids
    assert "git" in pkg_ids
    assert "uv" in pkg_ids
    assert "systemd" in pkg_ids

    # By default in mock driver, all packages are marked installed
    assert all(p.installed for p in packages)
    nginx_pkg = next(p for p in packages if p.id == "nginx")
    assert "1.24" in nginx_pkg.version


@pytest.mark.asyncio
async def test_missing_packages_detection_and_install():
    driver = package_manager.driver
    # Simulate a missing package
    if "python3-certbot-nginx" in driver.mock_installed_packages:
        driver.mock_installed_packages.remove("python3-certbot-nginx")

    missing = await package_manager.get_missing_packages()
    assert any(p.id == "python3-certbot-nginx" for p in missing)

    # Stream installation of missing packages
    log_lines = []
    async for line in package_manager.install_all_missing():
        log_lines.append(line)

    assert len(log_lines) > 0
    assert "python3-certbot-nginx" in driver.mock_installed_packages

    # Verify no longer missing
    missing_after = await package_manager.get_missing_packages()
    assert not any(p.id == "python3-certbot-nginx" for p in missing_after)


@pytest.mark.asyncio
async def test_install_packages_stream_single():
    driver = package_manager.driver
    if "git" in driver.mock_installed_packages:
        driver.mock_installed_packages.remove("git")

    lines = []
    async for line in package_manager.install_packages_stream(["git"]):
        lines.append(line)

    assert any("git" in l.lower() for l in lines)
    assert "git" in driver.mock_installed_packages
