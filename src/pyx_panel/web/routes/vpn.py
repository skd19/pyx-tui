"""WireGuard VPN management web routes."""
from __future__ import annotations

from urllib.parse import quote_plus
from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pyx_panel.services.package_manager import package_manager
from pyx_panel.services.wireguard_manager import (
    WireGuardPeerForm,
    WireGuardSettingsForm,
    WireGuardSetupForm,
    wireguard_manager,
)
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/vpn", dependencies=[Depends(require_auth)])


def _vpn_redirect(msg: str = "", error: str = "") -> RedirectResponse:
    if error:
        return RedirectResponse(
            url=f"/vpn?error={quote_plus(error)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/vpn?msg={quote_plus(msg)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("", response_class=HTMLResponse)
async def vpn_dashboard(request: Request, msg: str = "", error: str = ""):
    server_status = await wireguard_manager.get_status()
    peers = await wireguard_manager.list_peers()

    # Check package status
    packages = await package_manager.get_packages()
    wg_pkg = next((p for p in packages if p.id == "wireguard"), None)
    wg_tools_pkg = next((p for p in packages if p.id == "wireguard-tools"), None)

    packages_installed = (wg_pkg.installed if wg_pkg else True) and (wg_tools_pkg.installed if wg_tools_pkg else True)

    # Next preview IP
    next_ip = wireguard_manager._get_next_available_ip()

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="vpn.html",
        context={
            "active_tab": "vpn",
            "server": server_status,
            "peers": peers,
            "packages_installed": packages_installed,
            "next_ip": next_ip,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/setup")
async def setup_wireguard(
    server_port: int = Form(51820),
    server_ip: str = Form(""),
    subnet: str = Form("10.8.0.1/24"),
    dns: str = Form("1.1.1.1, 1.0.0.1"),
    network_interface: str = Form(""),
):
    form = WireGuardSetupForm(
        server_port=server_port,
        server_ip=server_ip.strip(),
        subnet=subnet.strip(),
        dns=dns.strip(),
        network_interface=network_interface.strip(),
    )
    ok, message = await wireguard_manager.setup_server(form)
    if not ok:
        return _vpn_redirect(error=message)
    return _vpn_redirect(msg=message)


@router.post("/start")
async def start_wireguard():
    ok, message = await wireguard_manager.start_server()
    if not ok:
        return _vpn_redirect(error=message)
    return _vpn_redirect(msg=message)


@router.post("/stop")
async def stop_wireguard():
    ok, message = await wireguard_manager.stop_server()
    if not ok:
        return _vpn_redirect(error=message)
    return _vpn_redirect(msg=message)


@router.post("/peer/add")
async def add_peer(
    name: str = Form(...),
    use_psk: bool = Form(True),
    tunnel_mode: str = Form("full"),
    dns: str = Form("1.1.1.1, 1.0.0.1"),
):
    form = WireGuardPeerForm(
        name=name.strip(),
        use_psk=use_psk,
        tunnel_mode=tunnel_mode.strip(),
        dns=dns.strip(),
    )
    ok, message, _ = await wireguard_manager.add_peer(form)
    if not ok:
        return _vpn_redirect(error=message)
    return _vpn_redirect(msg=message)


@router.post("/peer/{name}/toggle")
async def toggle_peer(name: str):
    ok, message = await wireguard_manager.toggle_peer(name)
    if not ok:
        return _vpn_redirect(error=message)
    return _vpn_redirect(msg=message)


@router.post("/peer/{name}/delete")
async def delete_peer(name: str):
    ok, message = await wireguard_manager.delete_peer(name)
    if not ok:
        return _vpn_redirect(error=message)
    return _vpn_redirect(msg=message)


@router.get("/peer/{name}/config")
async def get_peer_config(name: str):
    conf_text = await wireguard_manager.generate_client_config(name)
    if not conf_text:
        return JSONResponse(status_code=404, content={"error": f"Peer '{name}' not found"})
    return JSONResponse(content={"name": name, "config": conf_text})


@router.get("/peer/{name}/download")
async def download_peer_config(name: str):
    conf_text = await wireguard_manager.generate_client_config(name)
    if not conf_text:
        return _vpn_redirect(error=f"Peer '{name}' not found")
    filename = f"{name}.conf"
    return Response(
        content=conf_text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/settings")
async def update_settings(
    server_port: int = Form(51820),
    server_ip: str = Form(""),
    dns: str = Form("1.1.1.1, 1.0.0.1"),
):
    form = WireGuardSettingsForm(
        server_port=server_port,
        server_ip=server_ip.strip(),
        dns=dns.strip(),
    )
    ok, message = await wireguard_manager.update_settings(form)
    if not ok:
        return _vpn_redirect(error=message)
    return _vpn_redirect(msg=message)
