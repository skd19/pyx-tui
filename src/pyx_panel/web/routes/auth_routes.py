"""Authentication endpoints for login and logout."""
from __future__ import annotations

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pyx_panel.config import settings
from pyx_panel.web.auth import COOKIE_NAME, create_session_token

router = APIRouter()


def get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    templates = get_templates(request)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": error},
    )


@router.post("/login")
async def login_submit(request: Request, token: str = Form(...)):
    expected_token = settings.get_token()
    clean_token = token.strip()

    if clean_token != expected_token:
        templates = get_templates(request)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid access token. Please check the terminal output for the correct token.",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Success: set signed session cookie
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    cookie_value = create_session_token(clean_token)
    response.set_cookie(
        key=COOKIE_NAME,
        value=cookie_value,
        httponly=True,
        samesite="lax",
        max_age=86400 * 7,
    )
    return response


@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key=COOKIE_NAME)
    return response
