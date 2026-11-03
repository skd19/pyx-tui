"""Unit tests for authentication and session management."""
import pytest
from pyx_panel.config import settings
from pyx_panel.web.auth import create_session_token, verify_session_cookie


def test_token_generation():
    token = settings.get_token()
    assert token != ""
    assert len(token) >= 20
    # Calling it again returns the same token
    assert settings.get_token() == token


def test_session_cookie_signature():
    token = settings.get_token()
    cookie_val = create_session_token(token)
    assert cookie_val != ""
    assert verify_session_cookie(cookie_val) is True


def test_invalid_session_cookie():
    assert verify_session_cookie(None) is False
    assert verify_session_cookie("tampered.fake.cookie") is False
    assert verify_session_cookie("") is False
