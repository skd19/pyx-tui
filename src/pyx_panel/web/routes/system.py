"""System-level operations: Nginx testing, global reloading, watchdog status, and panel shutdown."""
from __future__ import annotations

import asyncio
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pyx_panel.config import settings
from pyx_panel.core import get_driver
from pyx_panel.core.watchdog import watchdog
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/api/system", dependencies=[Depends(require_auth)])


@router.post("/test-nginx")
async def test_nginx():
    """Runs nginx -t and returns result."""
    driver = get_driver()
    is_valid, output = await driver.test_nginx()
    return JSONResponse(
        {
            "valid": is_valid,
            "output": output,
        }
    )


@router.post("/reload-nginx")
async def reload_nginx():
    """Validates and reloads Nginx."""
    driver = get_driver()
    success, msg = await driver.reload_nginx()
    return JSONResponse(
        {
            "success": success,
            "message": msg,
        }
    )


@router.get("/watchdog")
async def watchdog_status():
    """Returns remaining seconds before idle shutdown."""
    remaining = watchdog.get_remaining_seconds()
    return JSONResponse(
        {
            "remaining_seconds": remaining,
            "timeout_minutes": settings.idle_timeout_minutes,
        }
    )


@router.post("/shutdown")
async def shutdown_panel():
    """Triggers clean shutdown of the panel from the UI."""
    # Schedule shutdown shortly so response can be delivered to browser
    asyncio.create_task(_delayed_shutdown())
    return JSONResponse(
        {
            "status": "shutting_down",
            "message": "pyx-panel is shutting down. You can safely close this browser tab.",
        }
    )


async def _delayed_shutdown():
    await asyncio.sleep(0.5)
    await watchdog.trigger_shutdown(reason="User clicked 'Shutdown' in Web UI")
