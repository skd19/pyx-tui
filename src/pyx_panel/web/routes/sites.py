"""Nginx site configuration routes (CRUD, reverse proxy generator, raw editor)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pyx_panel.services.nginx_manager import (
    ReverseProxyForm,
    StaticSiteForm,
    nginx_manager,
)
from pyx_panel.services.service_manager import service_manager
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/sites", dependencies=[Depends(require_auth)])


@router.get("", response_class=HTMLResponse)
async def list_sites(request: Request, msg: str = "", error: str = ""):
    sites = nginx_manager.list_sites()
    # Also fetch services so the user can easily pick an upstream port
    services = await service_manager.list_services()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="sites.html",
        context={
            "active_tab": "sites",
            "sites": sites,
            "services": services,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/new/reverse-proxy")
async def create_reverse_proxy(
    request: Request,
    name: str = Form(...),
    domains: str = Form(...),
    upstream: str = Form(...),
    www_handling: str = Form("none"),
    enable_websocket: bool = Form(False),
    client_max_body_size: str = Form("50M"),
    enable_immediately: bool = Form(True),
):
    form = ReverseProxyForm(
        name=name,
        domains=domains,
        upstream=upstream,
        www_handling=www_handling,
        enable_websocket=enable_websocket,
        client_max_body_size=client_max_body_size,
        enable_immediately=enable_immediately,
    )
    config = nginx_manager.generate_reverse_proxy_config(form)
    success, msg = await nginx_manager.save_and_validate_site(
        name=form.name,
        content=config,
        enable_if_new=form.enable_immediately,
    )
    if not success:
        return RedirectResponse(
            url=f"/sites?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/sites?msg=Site '{form.name}' created successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/new/static")
async def create_static_site(
    request: Request,
    name: str = Form(...),
    domains: str = Form(...),
    root_path: str = Form(...),
    www_handling: str = Form("none"),
    spa_fallback: bool = Form(True),
    enable_immediately: bool = Form(True),
):
    form = StaticSiteForm(
        name=name,
        domains=domains,
        root_path=root_path,
        www_handling=www_handling,
        spa_fallback=spa_fallback,
        enable_immediately=enable_immediately,
    )
    config = nginx_manager.generate_static_config(form)
    success, msg = await nginx_manager.save_and_validate_site(
        name=form.name,
        content=config,
        enable_if_new=form.enable_immediately,
    )
    if not success:
        return RedirectResponse(
            url=f"/sites?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/sites?msg=Site '{form.name}' created successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{name}", response_class=HTMLResponse)
async def view_site_editor(request: Request, name: str, msg: str = "", error: str = ""):
    site = nginx_manager.get_site(name)
    if not site:
        return RedirectResponse(url="/sites?error=Site not found", status_code=status.HTTP_303_SEE_OTHER)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="site_editor.html",
        context={
            "active_tab": "sites",
            "site": site,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/{name}/save")
async def save_raw_site(
    request: Request,
    name: str,
    content: str = Form(...),
):
    success, msg = await nginx_manager.save_and_validate_site(
        name=name,
        content=content,
    )
    if not success:
        return RedirectResponse(
            url=f"/sites/{name}?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/sites/{name}?msg=Configuration saved and verified successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/{name}/toggle")
async def toggle_site(name: str):
    site = nginx_manager.get_site(name)
    if not site:
        return RedirectResponse(url="/sites?error=Site not found", status_code=status.HTTP_303_SEE_OTHER)

    if site.enabled:
        _, msg = await nginx_manager.disable_site(name)
    else:
        _, msg = await nginx_manager.enable_site(name)

    return RedirectResponse(url=f"/sites?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{name}/delete")
async def delete_site(name: str):
    _, msg = await nginx_manager.delete_site(name)
    return RedirectResponse(url=f"/sites?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{name}/remove-ssl")
async def remove_site_ssl(name: str):
    success, msg = await nginx_manager.remove_ssl_from_site(name)
    if not success:
        return RedirectResponse(url=f"/sites?error={msg}", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url=f"/sites?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)
