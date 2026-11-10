"""Main FastAPI application definition and lifespan management."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pyx_panel.config import settings
from pyx_panel.core.watchdog import ActivityTrackingMiddleware, watchdog
from pyx_panel.web.routes import (
    auth_routes,
    dashboard,
    firewall,
    logs,
    packages,
    security,
    services,
    sites,
    ssl,
    system,
    vpn,
    wordpress,
)
from pyx_panel.services.ufw_manager import ufw_manager

logger = logging.getLogger("pyx_panel")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing pyx-panel...")
    # 1. Ephemeral firewall port: open panel port if UFW is active
    try:
        ok, msg = await ufw_manager.open_panel_port(settings.panel_port)
        logger.info(f"Firewall startup: {msg}")
    except Exception as e:
        logger.warning(f"Could not configure firewall startup port: {e}")

    # 2. Start watchdog (server ref will be set if launched through CLI runner)
    await watchdog.start()
    yield

    # Shutdown
    # 1. Stop watchdog
    await watchdog.stop()

    # 2. Ephemeral firewall port: close panel port when stopping
    try:
        ok, msg = await ufw_manager.close_panel_port(settings.panel_port)
        logger.info(f"Firewall shutdown: {msg}")
    except Exception as e:
        logger.warning(f"Could not cleanup firewall shutdown port: {e}")

    logger.info("pyx-panel stopped.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="pyx-panel",
        description="On-Demand VPS Nginx & Systemd Service Manager",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Add activity tracker middleware for auto-shutdown watchdog
    app.add_middleware(ActivityTrackingMiddleware)

    # Setup Jinja2 templates
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates = templates

    # Mount static files
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Include routers
    app.include_router(auth_routes.router)
    app.include_router(dashboard.router)
    app.include_router(sites.router)
    app.include_router(wordpress.router)
    app.include_router(services.router)
    app.include_router(logs.router)
    app.include_router(ssl.router)
    app.include_router(firewall.router)
    app.include_router(vpn.router)
    app.include_router(security.router)
    app.include_router(packages.router)
    app.include_router(system.router)

    return app


app = create_app()
