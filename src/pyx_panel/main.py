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
    logs,
    services,
    sites,
    ssl,
    system,
)

logger = logging.getLogger("pyx_panel")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing pyx-panel...")
    # Start watchdog (server ref will be set if launched through CLI runner)
    await watchdog.start()
    yield
    # Shutdown
    await watchdog.stop()
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
    app.include_router(services.router)
    app.include_router(logs.router)
    app.include_router(ssl.router)
    app.include_router(system.router)

    return app


app = create_app()
