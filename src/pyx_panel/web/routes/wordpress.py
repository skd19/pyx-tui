"""WordPress management web routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pyx_panel.services.package_manager import package_manager
from pyx_panel.services.wordpress_manager import (
    WordPressDeployForm,
    wordpress_manager,
)
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/wordpress", dependencies=[Depends(require_auth)])


@router.get("", response_class=HTMLResponse)
async def wordpress_dashboard(request: Request, msg: str = "", error: str = ""):
    wp_sites = wordpress_manager.list_wordpress_sites()
    php_sockets = await wordpress_manager.detect_php_sockets()

    # Check prerequisites status from package catalog
    packages = await package_manager.get_packages()
    php_pkg = next((p for p in packages if p.id == "php-fpm"), None)
    db_pkg = next((p for p in packages if p.id == "mariadb-server"), None)
    wp_cli_pkg = next((p for p in packages if p.id == "wp-cli"), None)

    php_installed = php_pkg.installed if php_pkg else False
    db_installed = db_pkg.installed if db_pkg else False
    wp_cli_installed = wp_cli_pkg.installed if wp_cli_pkg else False

    total_sites = len(wp_sites)
    ssl_count = sum(1 for s in wp_sites if s.ssl_enabled)
    ssl_percentage = int((ssl_count / total_sites * 100)) if total_sites > 0 else 100

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="wordpress.html",
        context={
            "active_tab": "wordpress",
            "wp_sites": wp_sites,
            "php_sockets": php_sockets,
            "php_installed": php_installed,
            "db_installed": db_installed,
            "wp_cli_installed": wp_cli_installed,
            "php_version": php_pkg.version if (php_pkg and php_pkg.version) else "8.2",
            "db_version": db_pkg.version if (db_pkg and db_pkg.version) else "MariaDB",
            "total_sites": total_sites,
            "ssl_percentage": ssl_percentage,
            "msg": msg,
            "error": error,
        },
    )


@router.post("/new")
async def create_wordpress_site(
    name: str = Form(...),
    domains: str = Form(...),
    www_handling: str = Form("none"),
    root_path: str = Form(""),
    php_socket: str = Form(""),
    create_db: bool = Form(True),
    db_name: str = Form(""),
    db_user: str = Form(""),
    db_pass: str = Form(""),
    block_xmlrpc: bool = Form(True),
    block_upload_php: bool = Form(True),
    client_max_body_size: str = Form("64M"),
    enable_immediately: bool = Form(True),
):
    form = WordPressDeployForm(
        name=name,
        domains=domains,
        www_handling=www_handling,
        root_path=root_path,
        php_socket=php_socket,
        create_db=create_db,
        db_name=db_name,
        db_user=db_user,
        db_pass=db_pass,
        download_core=True,
        block_xmlrpc=block_xmlrpc,
        block_upload_php=block_upload_php,
        client_max_body_size=client_max_body_size,
        enable_immediately=enable_immediately,
    )
    success, msg = await wordpress_manager.deploy_wordpress_site(form)
    if not success:
        return RedirectResponse(
            url=f"/wordpress?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/wordpress?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/{site_name}/maintenance")
async def toggle_maintenance(site_name: str):
    success, msg = await wordpress_manager.toggle_maintenance_mode(site_name)
    if not success:
        return RedirectResponse(
            url=f"/wordpress?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/wordpress?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/{site_name}/backup")
async def backup_db(site_name: str):
    success, msg, _ = await wordpress_manager.backup_database(site_name)
    if not success:
        return RedirectResponse(
            url=f"/wordpress?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/wordpress?msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/{site_name}/delete")
async def delete_site(site_name: str):
    success, msg = await wordpress_manager.delete_wordpress_site(site_name)
    if not success:
        return RedirectResponse(
            url=f"/wordpress?error={msg}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/wordpress?msg=WordPress site '{site_name}' deleted successfully",
        status_code=status.HTTP_303_SEE_OTHER,
    )
