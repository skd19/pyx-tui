"""Web routes for VPS Security Center, Vulnerability Auditing, and Threat Mitigation."""
from __future__ import annotations

from urllib.parse import quote_plus
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from pyx_panel.config import settings
from pyx_panel.services.security_manager import security_manager
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/security", dependencies=[Depends(require_auth)])


def _sec_redirect(msg: str = "", error: str = "") -> RedirectResponse:
    if error:
        return RedirectResponse(
            url=f"/security?error={quote_plus(error)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/security?msg={quote_plus(msg)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("", response_class=HTMLResponse)
async def security_page(request: Request, msg: str = "", error: str = ""):
    report = await security_manager.run_security_audit()
    ssh_cfg = await security_manager.driver.read_ssh_config()
    has_ssh_keys = await security_manager.driver.has_ssh_authorized_keys()
    nginx_guard_active = security_manager.nginx_mgr.is_security_guard_active()
    default_deny_active = security_manager.nginx_mgr.is_default_deny_active()
    cf_shield_active = await security_manager.ufw_mgr.is_cloudflare_shield_active()

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="security.html",
        context={
            "active_tab": "security",
            "report": report,
            "ssh_cfg": ssh_cfg,
            "has_ssh_keys": has_ssh_keys,
            "nginx_guard_active": nginx_guard_active,
            "default_deny_active": default_deny_active,
            "cf_shield_active": cf_shield_active,
            "panel_port": settings.panel_port,
            "is_mock": settings.mock_system,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/audit/run")
async def run_audit():
    return _sec_redirect(msg="Security audit refreshed successfully")


@router.post("/nginx-guard/toggle")
async def toggle_nginx_guard():
    if security_manager.nginx_mgr.is_security_guard_active():
        success, msg = await security_manager.nginx_mgr.revert_security_guard()
    else:
        success, msg = await security_manager.nginx_mgr.apply_security_guard()

    if not success:
        return _sec_redirect(error=msg)
    return _sec_redirect(msg=msg)


@router.post("/direct-ip-drop/toggle")
async def toggle_direct_ip_drop():
    if security_manager.nginx_mgr.is_default_deny_active():
        success, msg = await security_manager.nginx_mgr.disable_default_deny()
    else:
        success, msg = await security_manager.nginx_mgr.enable_default_deny()

    if not success:
        return _sec_redirect(error=msg)
    return _sec_redirect(msg=msg)


@router.post("/ssh/harden")
async def harden_ssh(mode: str = Form("full")):
    if mode == "keys_only":
        success, msg = await security_manager.harden_ssh_keys_only()
    elif mode == "root_only":
        success, msg = await security_manager.restrict_ssh_root()
    else:
        success, msg = await security_manager.harden_ssh_full()

    if not success:
        return _sec_redirect(error=msg)
    return _sec_redirect(msg=msg)


@router.post("/kernel/harden")
async def harden_kernel():
    success, msg = await security_manager.apply_kernel_hardening()
    if not success:
        return _sec_redirect(error=msg)
    return _sec_redirect(msg=msg)


@router.post("/ports/isolate")
async def isolate_port(port: str = Form(...), proto: str = Form("tcp")):
    success, msg = await security_manager.isolate_port_ufw(port, proto=proto)
    if not success:
        return _sec_redirect(error=msg)
    return _sec_redirect(msg=f"Port {port}/{proto} isolated: {msg}")


@router.post("/harden-all")
async def harden_all():
    results = await security_manager.harden_all()
    failed = [k for k, (ok, _) in results.items() if not ok]
    if failed:
        err_details = "; ".join(f"{k}: {msg}" for k, (ok, msg) in results.items() if not ok)
        return _sec_redirect(error=f"Hardening completed with issues: {err_details}")

    return _sec_redirect(msg="All security hardening modules applied successfully! UFW, Nginx Guard, Direct IP Drop, Kernel, and SSH are hardened.")
