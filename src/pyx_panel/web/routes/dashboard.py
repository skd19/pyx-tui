"""Dashboard views and system overview endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pyx_panel.config import settings
from pyx_panel.core import get_driver
from pyx_panel.core.watchdog import watchdog
from pyx_panel.services.certbot_manager import certbot_manager
from pyx_panel.services.nginx_manager import nginx_manager
from pyx_panel.services.service_manager import service_manager
from pyx_panel.web.auth import COOKIE_NAME, create_session_token, require_auth

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard_index(request: Request, token: str | None = None):
    # If ?token= query parameter provided and matches, auto-authenticate with cookie
    expected_token = settings.get_token()
    if token and token == expected_token:
        response = RedirectResponse(url="/", status_code=303)
        cookie_val = create_session_token(token)
        response.set_cookie(
            key=COOKIE_NAME,
            value=cookie_val,
            httponly=True,
            samesite="lax",
            max_age=86400 * 7,
        )
        return response

    # Otherwise verify authentication
    await require_auth(request)

    driver = get_driver()
    nginx_status = await driver.get_nginx_status()
    sites = nginx_manager.list_sites()
    services = await service_manager.list_services()
    certs = await certbot_manager.list_certificates()
    public_ip = await certbot_manager.get_public_ip()

    active_services = sum(1 for s in services if s.active)
    enabled_sites = sum(1 for s in sites if s.enabled)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_tab": "dashboard",
            "nginx_status": nginx_status,
            "sites": sites,
            "services": services,
            "certs": certs,
            "public_ip": public_ip,
            "active_services": active_services,
            "enabled_sites": enabled_sites,
            "idle_timeout_min": settings.idle_timeout_minutes,
            "is_mock": settings.mock_system,
        },
    )
