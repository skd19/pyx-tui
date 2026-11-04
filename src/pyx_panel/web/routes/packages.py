"""Web routes for system package inspection and prerequisite installation."""
from __future__ import annotations

import asyncio
from urllib.parse import quote_plus
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from pyx_panel.config import settings
from pyx_panel.services.package_manager import package_manager
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/packages", dependencies=[Depends(require_auth)])


def _pkg_redirect(msg: str = "", error: str = "") -> RedirectResponse:
    if error:
        return RedirectResponse(
            url=f"/packages?error={quote_plus(error)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/packages?msg={quote_plus(msg)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("", response_class=HTMLResponse)
async def packages_page(request: Request, msg: str = "", error: str = ""):
    packages = await package_manager.get_packages()
    missing = [p for p in packages if not p.installed]
    installed = [p for p in packages if p.installed]

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="packages.html",
        context={
            "active_tab": "packages",
            "packages": packages,
            "missing_count": len(missing),
            "installed_count": len(installed),
            "total_count": len(packages),
            "has_missing": len(missing) > 0,
            "is_mock": settings.mock_system,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/install-all")
async def install_all_packages():
    missing = await package_manager.get_missing_packages()
    if not missing:
        return _pkg_redirect(msg="All prerequisite packages are already installed")

    # Collect lines
    output_lines = []
    async for line in package_manager.install_all_missing():
        output_lines.append(line)

    return _pkg_redirect(msg=f"Successfully installed {len(missing)} missing prerequisite package(s)")


@router.post("/{pkg_id}/install")
async def install_single_package(pkg_id: str):
    output_lines = []
    async for line in package_manager.install_packages_stream([pkg_id]):
        output_lines.append(line)

    return _pkg_redirect(msg=f"Package {pkg_id} installed and configured successfully")


@router.get("/install/stream")
async def stream_package_install(pkgs: str = ""):
    """Streams live installation logs over Server-Sent Events (SSE)."""
    if pkgs.strip():
        pkg_ids = [p.strip() for p in pkgs.split(",") if p.strip()]
        stream_gen = package_manager.install_packages_stream(pkg_ids)
    else:
        stream_gen = package_manager.install_all_missing()

    async def event_generator():
        yield "data: [pyx-panel] Initializing package installation environment...\n\n"
        await asyncio.sleep(0.05)
        async for line in stream_gen:
            clean_line = line.replace("\n", " ")
            yield f"data: {clean_line}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
