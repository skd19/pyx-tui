"""Driver package initialization and factory."""
from __future__ import annotations

from functools import lru_cache
from pyx_panel.config import settings
from pyx_panel.core.driver import SystemDriver
from pyx_panel.core.linux_driver import LinuxSystemDriver
from pyx_panel.core.mock_driver import MockSystemDriver


@lru_cache(maxsize=1)
def get_driver() -> SystemDriver:
    """Returns the singleton driver instance based on configuration."""
    if settings.mock_system:
        # Override paths to use mock directory
        mock = MockSystemDriver(base_dir=settings.mock_dir)
        settings.nginx_sites_available = mock.sites_available
        settings.nginx_sites_enabled = mock.sites_enabled
        settings.nginx_conf_d = mock.conf_d
        settings.systemd_system_dir = mock.systemd_dir
        return mock
    return LinuxSystemDriver()
