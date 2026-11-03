"""Firewall (UFW) management web routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pyx_panel.config import settings
from pyx_panel.services.nginx_manager import nginx_manager
from pyx_panel.services.ufw_manager import AddRuleForm, ufw_manager
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/firewall", dependencies=[Depends(require_auth)])


@router.get("", response_class=HTMLResponse)
async def firewall_page(request: Request, msg: str = "", error: str = ""):
    fw_status = await ufw_manager.get_status()
    cf_shield_active = await ufw_manager.is_cloudflare_shield_active()
    default_deny_active = nginx_manager.is_default_deny_active()

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="firewall.html",
        context={
            "active_tab": "firewall",
            "fw_status": fw_status,
            "cf_shield_active": cf_shield_active,
            "default_deny_active": default_deny_active,
            "panel_port": settings.panel_port,
            "is_mock": settings.mock_system,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/rule/add")
async def add_firewall_rule(
    port: str = Form(...),
    proto: str = Form("tcp"),
    action: str = Form("allow"),
    comment: str = Form(""),
):
    form = AddRuleForm(
        port=port,
        proto=proto,
        action=action,
        comment=comment,
    )
    success, msg = await ufw_manager.add_rule(form)
    if not success:
        return RedirectResponse(
            url=f"/firewall?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/firewall?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/rule/{index}/delete")
async def delete_firewall_rule(index: int):
    success, msg = await ufw_manager.delete_rule(index)
    if not success:
        return RedirectResponse(
            url=f"/firewall?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/firewall?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/toggle")
async def toggle_firewall(
    enable: bool = Form(True),
    auto_allow_ssh: bool = Form(True),
):
    success, msg = await ufw_manager.toggle_ufw(
        enable=enable,
        auto_allow_ssh=auto_allow_ssh,
        panel_port=settings.panel_port,
    )
    if not success:
        return RedirectResponse(
            url=f"/firewall?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/firewall?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/preset/web-baseline")
async def apply_web_baseline():
    success, msg = await ufw_manager.apply_baseline_security(panel_port=settings.panel_port)
    if not success:
        return RedirectResponse(
            url=f"/firewall?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/firewall?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/preset/cloudflare-shield")
async def apply_cloudflare_shield(block_app_port: str = Form("8080")):
    success, msg = await ufw_manager.apply_cloudflare_shield(
        panel_port=settings.panel_port,
        block_app_port=block_app_port,
    )
    if not success:
        return RedirectResponse(
            url=f"/firewall?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/firewall?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/preset/cloudflare-revert")
async def revert_cloudflare_shield():
    success, msg = await ufw_manager.revert_cloudflare_shield(panel_port=settings.panel_port)
    if not success:
        return RedirectResponse(
            url=f"/firewall?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/firewall?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/default-deny/toggle")
async def toggle_default_deny():
    if nginx_manager.is_default_deny_active():
        success, err = await nginx_manager.disable_default_deny()
        msg = "Direct IP reject disabled: standard Nginx fallback restored"
    else:
        success, err = await nginx_manager.enable_default_deny()
        msg = "Direct IP reject enabled: raw VPS IP connections and unknown hostnames dropped with 444"

    if not success:
        return RedirectResponse(
            url=f"/firewall?error={err}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/firewall?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
