"""Unit tests for the inactivity watchdog timer and auto-shutdown."""
import asyncio
import time
import pytest
from pyx_panel.core.watchdog import WatchdogManager


@pytest.mark.asyncio
async def test_watchdog_activity_tracking():
    # Watchdog with 1 minute timeout
    wd = WatchdogManager(timeout_minutes=1)
    assert wd.timeout_seconds == 60
    assert wd.get_remaining_seconds() <= 60
    assert wd.get_remaining_seconds() >= 55

    # Simulate activity
    wd.record_activity()
    assert wd.get_remaining_seconds() >= 59


@pytest.mark.asyncio
async def test_watchdog_shutdown_trigger():
    # Watchdog with 0.1 second timeout for fast testing
    wd = WatchdogManager(timeout_minutes=1)
    wd.timeout_seconds = 1  # 1 second timeout

    class FakeServer:
        should_exit = False

    fake_server = FakeServer()
    await wd.start(server=fake_server)

    # Initially not shutting down
    assert wd.is_shutting_down is False
    assert fake_server.should_exit is False

    # Trigger shutdown
    await wd.trigger_shutdown(reason="Test shutdown")
    assert wd.is_shutting_down is True
    assert fake_server.should_exit is True

    await wd.stop()
