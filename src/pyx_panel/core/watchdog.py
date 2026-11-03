"""Inactivity watchdog and auto-shutdown supervisor."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from typing import Optional
import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("pyx_panel.watchdog")


class WatchdogManager:
    """Monitors activity and triggers automatic shutdown on idle timeout."""

    def __init__(self, timeout_minutes: int = 15) -> None:
        self.timeout_seconds = timeout_minutes * 60
        self.last_activity_time = time.time()
        self.is_shutting_down = False
        self._watchdog_task: Optional[asyncio.Task] = None
        self.server: Optional[uvicorn.Server] = None

    def record_activity(self) -> None:
        """Update last active timestamp."""
        self.last_activity_time = time.time()

    def get_remaining_seconds(self) -> int:
        """Returns seconds remaining before automatic shutdown."""
        if self.timeout_seconds <= 0:
            return 999999
        elapsed = time.time() - self.last_activity_time
        remaining = max(0, int(self.timeout_seconds - elapsed))
        return remaining

    async def start(self, server: Optional[uvicorn.Server] = None) -> None:
        """Start the watchdog background monitor."""
        self.server = server
        if self.timeout_seconds > 0:
            self._watchdog_task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Cancel background task."""
        if self._watchdog_task and not self._watchdog_task.done():
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        """Periodically check for idle inactivity."""
        while not self.is_shutting_down:
            await asyncio.sleep(5)
            if self.timeout_seconds > 0:
                elapsed = time.time() - self.last_activity_time
                if elapsed >= self.timeout_seconds:
                    minutes = self.timeout_seconds // 60
                    print(
                        f"\n\033[93m[pyx-panel] Inactivity timeout: No user activity for {minutes}m. "
                        f"Automatically shutting down server for security.\033[0m\n",
                        flush=True,
                    )
                    await self.trigger_shutdown(reason="Inactivity timeout")
                    break

    async def trigger_shutdown(self, reason: str = "Manual request") -> None:
        """Trigger graceful shutdown of the server."""
        if self.is_shutting_down:
            return
        self.is_shutting_down = True
        print(f"\n[pyx-panel] Shutting down panel ({reason})...", flush=True)

        if self.server:
            self.server.should_exit = True
        else:
            # Send SIGINT to own process
            try:
                os.kill(os.getpid(), signal.SIGINT)
            except Exception:
                # Windows fallback
                try:
                    os.kill(os.getpid(), signal.SIGTERM)
                except Exception:
                    pass


# Global watchdog instance
watchdog = WatchdogManager()


class ActivityTrackingMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that records user activity timestamps."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Don't let background polling of remaining watchdog time keep the server awake
        path = request.url.path
        if not path.startswith("/api/system/watchdog") and not path.startswith("/static"):
            watchdog.record_activity()
        return await call_next(request)
