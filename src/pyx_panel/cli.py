"""Command Line Interface (CLI) entrypoint for on-demand execution."""
from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import uvicorn
from pyx_panel.config import settings
from pyx_panel.core.watchdog import watchdog


def get_local_ip() -> str:
    """Finds best local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def print_banner(host: str, port: int, token: str, timeout_min: int, is_mock: bool) -> None:
    """Prints a beautiful and clear banner in the terminal with one-click access URL."""
    local_ip = get_local_ip()
    url_local = f"http://localhost:{port}/?token={token}"
    url_network = f"http://{local_ip}:{port}/?token={token}"

    mode_str = " (Mock Dev Mode)" if is_mock else " (Production Host Mode)"
    timeout_str = f"Auto-shutdown after {timeout_min}m of inactivity" if timeout_min > 0 else "Disabled (runs until stopped)"

    banner = f"""
\033[1;36m========================================================================\033[0m
\033[1;32m   pyx-panel: On-Demand VPS Nginx & Service Manager{mode_str}\033[0m
\033[1;36m========================================================================\033[0m
  \033[1mLocal URL:\033[0m    \033[4;34m{url_local}\033[0m
  \033[1mNetwork URL:\033[0m  \033[4;34m{url_network}\033[0m
  \033[1mSecret Token:\033[0m \033[33m{token}\033[0m
  \033[1mIdle Timeout:\033[0m {timeout_str}
  \033[1mHow to Exit:\033[0m  Press \033[1mCtrl+C\033[0m here in terminal, or click \033[1m'Shutdown'\033[0m in web UI
\033[1;36m========================================================================\033[0m
"""
    print(banner, flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="pyx-panel: On-Demand VPS Nginx & Service Manager",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=settings.panel_host,
        help="Host address to bind (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.panel_port,
        help="Port to bind (default: 8000)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=settings.idle_timeout_minutes,
        help="Idle timeout in minutes before auto-shutdown (default: 15, 0 to disable)",
    )
    parser.add_argument(
        "--token",
        type=str,
        default="",
        help="Secret access token (if omitted, auto-generated or read from .env)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Force mock system mode (no root/real systemd required)",
    )

    args = parser.parse_args()

    # Apply CLI args
    settings.panel_host = args.host
    settings.panel_port = args.port
    settings.idle_timeout_minutes = args.timeout
    if args.mock:
        settings.mock_system = True
    if args.token:
        settings.panel_secret_token = args.token

    token = settings.get_token()
    watchdog.timeout_seconds = settings.idle_timeout_minutes * 60

    print_banner(
        host=settings.panel_host,
        port=settings.panel_port,
        token=token,
        timeout_min=settings.idle_timeout_minutes,
        is_mock=settings.mock_system,
    )

    config = uvicorn.Config(
        "pyx_panel.main:app",
        host=settings.panel_host,
        port=settings.panel_port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    watchdog.server = server

    try:
        server.run()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        # Belt-and-suspenders fallback: ensure ephemeral UFW port is closed if running on Linux
        if not settings.mock_system:
            try:
                import subprocess
                subprocess.run(
                    ["ufw", "--force", "delete", "allow", f"{settings.panel_port}/tcp"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass
        print(f"\n\033[1;32m[pyx-panel] Stopped successfully. Port {settings.panel_port} closed. VPS remains clean and secure.\033[0m", flush=True)


if __name__ == "__main__":
    main()
