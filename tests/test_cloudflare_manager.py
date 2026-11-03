import pytest
from unittest.mock import patch, MagicMock
from pyx_panel.services.cloudflare_manager import (
    CloudflareManager,
    CLOUDFLARE_IPV4_FALLBACK,
    CLOUDFLARE_IPV6_FALLBACK,
)


@pytest.mark.asyncio
async def test_cloudflare_manager_fallback():
    cm = CloudflareManager()
    # Force mock network error
    with patch("httpx2.AsyncClient.get", side_effect=Exception("Connection refused")):
        v4, v6 = await cm.get_cloudflare_ips()
        assert v4 == CLOUDFLARE_IPV4_FALLBACK
        assert v6 == CLOUDFLARE_IPV6_FALLBACK


@pytest.mark.asyncio
async def test_cloudflare_manager_live_mock():
    cm = CloudflareManager()
    
    mock_v4_resp = MagicMock(status_code=200, text="1.1.1.0/24\n1.0.0.0/24\n")
    mock_v6_resp = MagicMock(status_code=200, text="2400:cb00::/32\n")

    async def mock_get(url, *args, **kwargs):
        if "ips-v4" in url:
            return mock_v4_resp
        return mock_v6_resp

    with patch("httpx2.AsyncClient.get", side_effect=mock_get):
        v4, v6 = await cm.get_cloudflare_ips()
        assert v4 == ["1.1.1.0/24", "1.0.0.0/24"]
        assert v6 == ["2400:cb00::/32"]

        # Test caching: second call returns cached without making requests
        cached_v4, cached_v6 = await cm.get_cloudflare_ips()
        assert cached_v4 == v4
        assert cached_v6 == v6
