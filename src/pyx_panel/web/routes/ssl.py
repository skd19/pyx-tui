"""SSL and Certbot certificate provisioning routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pyx_panel.services.certbot_manager import certbot_manager
from pyx_panel.services.nginx_manager import nginx_manager
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/ssl", dependencies=[Depends(require_auth)])


@router.get("", response_class=HTMLResponse)
async def ssl_page(request: Request, msg: str = "", error: str = ""):
    certs = await certbot_manager.list_certificates()
    sites = nginx_manager.list_sites()
    public_ip = await certbot_manager.get_public_ip()

    # Collect domains from all sites that could need SSL
    available_domains = []
    for s in sites:
        for d in s.domains:
            if d not in available_domains:
                available_domains.append(d)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="ssl.html",
        context={
            "active_tab": "ssl",
            "certs": certs,
            "sites": sites,
            "public_ip": public_ip,
            "available_domains": available_domains,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/check-dns")
async def check_dns(domain: str = Form(...)):
    """API endpoint to pre-check domain DNS A record resolution."""
    res = await certbot_manager.check_domain_dns(domain)
    return JSONResponse(
        {
            "domain": res.domain,
            "vps_ip": res.vps_ip,
            "domain_ips": res.domain_ips,
            "matches": res.matches,
            "error": res.error,
        }
    )


@router.post("/provision")
async def provision_ssl(
    domain: str = Form(...),
    email: str = Form(""),
    force: bool = Form(False),
):
    success, msg = await certbot_manager.provision_certificate(
        domain=domain,
        email=email,
        force=force,
    )
    if not success:
        return RedirectResponse(
            url=f"/ssl?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/ssl?msg=Certificate successfully issued for {domain}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
