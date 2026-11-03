"""Unit tests for systemd service manager."""
import pytest
from pyx_panel.services.service_manager import ServiceForm, ServiceManager


@pytest.fixture
def manager():
    return ServiceManager()


def test_generate_unit_content(manager):
    form = ServiceForm(
        name="test-go-app",
        description="Test Go Application",
        exec_start="/opt/apps/test-go/server",
        working_dir="/opt/apps/test-go",
        user="root",
        environment="PORT=9090\nGIN_MODE=release",
        restart="always",
        restart_sec="5s",
    )
    unit = manager.generate_unit_content(form)
    assert "[Unit]" in unit
    assert "Description=Test Go Application" in unit
    assert "ExecStart=/opt/apps/test-go/server" in unit
    assert "WorkingDirectory=/opt/apps/test-go" in unit
    assert 'Environment="PORT=9090"' in unit
    assert 'Environment="GIN_MODE=release"' in unit
    assert "Restart=always" in unit


@pytest.mark.asyncio
async def test_service_lifecycle(manager):
    form = ServiceForm(
        name="unit-test-app",
        description="Unit Test Application",
        exec_start="/usr/bin/true",
        autostart=False,
    )
    # Create
    success, _ = await manager.create_or_update_service(form)
    assert success is True

    # Check list
    services = await manager.list_services()
    found = any(s.name == "unit-test-app" for s in services)
    assert found is True

    # Start
    ok_start, _ = await manager.start("unit-test-app")
    assert ok_start is True

    # Stop
    ok_stop, _ = await manager.stop("unit-test-app")
    assert ok_stop is True

    # Delete
    ok_del, _ = await manager.delete("unit-test-app")
    assert ok_del is True
