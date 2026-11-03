"""Authentication and session management."""
from __future__ import annotations

from itsdangerous import BadSignature, URLSafeTimedSerializer
from fastapi import Cookie, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pyx_panel.config import settings

COOKIE_NAME = "pyx_session"


def get_serializer() -> URLSafeTimedSerializer:
    """Returns serializer for signed session cookies."""
    return URLSafeTimedSerializer(settings.get_session_secret())


def create_session_token(token: str) -> str:
    """Signs the authenticated session token."""
    s = get_serializer()
    return s.dumps({"token": token})


def verify_session_cookie(cookie_val: str | None) -> bool:
    """Validates session cookie signature and token match."""
    if not cookie_val:
        return False
    s = get_serializer()
    try:
        data = s.loads(cookie_val, max_age=86400 * 7)  # 7 days max age
        expected_token = settings.get_token()
        return data.get("token") == expected_token
    except (BadSignature, Exception):
        return False


async def require_auth(
    request: Request,
    token: str | None = None,
    pyx_session: str | None = None,
) -> bool:
    """
    Dependency that enforces authentication.
    Accepts:
    1. Valid signed session cookie
    2. URL query param `?token=...`
    3. Bearer token in Authorization header
    """
    expected_token = settings.get_token()

    # 1. Check direct query param token
    query_token = token or request.query_params.get("token")
    if query_token and query_token == expected_token:
        return True

    # 2. Check signed session cookie (from param or request.cookies)
    cookie_val = pyx_session if pyx_session is not None else request.cookies.get(COOKIE_NAME)
    if verify_session_cookie(cookie_val):
        return True

    # 3. Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        header_token = auth_header[7:].strip()
        if header_token == expected_token:
            return True

    # If it's an HTMX request, tell HTMX to redirect to /login
    if request.headers.get("HX-Request"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"HX-Redirect": "/login"},
        )

    # For browser navigation, redirect to /login
    raise HTTPException(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Location": "/login"},
    )
