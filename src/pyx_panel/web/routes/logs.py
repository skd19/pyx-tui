"""Server-Sent Events (SSE) live journalctl log streaming."""
from __future__ import annotations

import asyncio
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pyx_panel.core import get_driver
from pyx_panel.web.auth import require_auth

router = APIRouter(prefix="/services", dependencies=[Depends(require_auth)])


@router.get("/{name}/logs/stream")
async def stream_logs(request: Request, name: str, lines: int = 50):
    """Streams real-time journalctl logs for a service over SSE."""
    driver = get_driver()
    unit_name = name if name.endswith(".service") else f"{name}.service"

    async def event_generator():
        try:
            async for log_line in driver.stream_journal_logs(unit_name, lines=lines):
                if await request.is_disconnected():
                    break
                # Format for SSE
                yield f"data: {log_line}\n\n"
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
