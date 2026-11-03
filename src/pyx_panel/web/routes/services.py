"""Systemd service management routes (Go backend apps, process lifecycle, unit editor)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pyx_panel.services.service_manager import ServiceForm, service_manager
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/services", dependencies=[Depends(require_auth)])


@router.get("", response_class=HTMLResponse)
async def list_services(request: Request, msg: str = "", error: str = ""):
    services = await service_manager.list_services()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="services.html",
        context={
            "active_tab": "services",
            "services": services,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/new")
async def create_service(
    name: str = Form(...),
    description: str = Form("Backend Application"),
    exec_start: str = Form(...),
    working_dir: str = Form(""),
    user: str = Form("root"),
    environment: str = Form(""),
    restart: str = Form("always"),
    restart_sec: str = Form("5s"),
    autostart: bool = Form(True),
):
    form = ServiceForm(
        name=name,
        description=description,
        exec_start=exec_start,
        working_dir=working_dir,
        user=user,
        environment=environment,
        restart=restart,
        restart_sec=restart_sec,
        autostart=autostart,
    )
    success, msg = await service_manager.create_or_update_service(form)
    if not success:
        return RedirectResponse(
            url=f"/services?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/services?msg=Service '{form.name}' created and started successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{name}", response_class=HTMLResponse)
async def view_service_editor(request: Request, name: str, msg: str = "", error: str = ""):
    service = await service_manager.get_service(name)
    if not service:
        return RedirectResponse(url="/services?error=Service not found", status_code=status.HTTP_303_SEE_OTHER)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="service_editor.html",
        context={
            "active_tab": "services",
            "service": service,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/{name}/save")
async def save_raw_unit(name: str, content: str = Form(...)):
    success, msg = await service_manager.save_raw_unit(name, content)
    if not success:
        return RedirectResponse(
            url=f"/services/{name}?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/services/{name}?msg=Service unit updated and daemon reloaded",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/{name}/start")
async def start_service(name: str):
    _, msg = await service_manager.start(name)
    return RedirectResponse(url=f"/services?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{name}/stop")
async def stop_service(name: str):
    _, msg = await service_manager.stop(name)
    return RedirectResponse(url=f"/services?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{name}/restart")
async def restart_service(name: str):
    _, msg = await service_manager.restart(name)
    return RedirectResponse(url=f"/services?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{name}/toggle-enable")
async def toggle_service_enable(name: str):
    service = await service_manager.get_service(name)
    if not service:
        return RedirectResponse(url="/services?error=Service not found", status_code=status.HTTP_303_SEE_OTHER)

    if service.unit_file_state == "enabled":
        _, msg = await service_manager.disable(name)
    else:
        _, msg = await service_manager.enable(name)

    return RedirectResponse(url=f"/services?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{name}/delete")
async def delete_service(name: str):
    _, msg = await service_manager.delete(name)
    return RedirectResponse(url=f"/services?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)
