"""Cloudflare IP ranges provider and proxy detection manager."""
from __future__ import annotations

import logging
import httpx2

logger = logging.getLogger("pyx_panel.cloudflare")

# Official Cloudflare published IP ranges (fallback constants in case network is down)
CLOUDFLARE_IPV4_FALLBACK = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CLOUDFLARE_IPV6_FALLBACK = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]


class CloudflareManager:
    """Manages Cloudflare IP range retrieval and shield status."""

    def __init__(self) -> None:
        self._cached_ipv4: list[str] = []
        self._cached_ipv6: list[str] = []

    async def get_cloudflare_ips(self) -> tuple[list[str], list[str]]:
        """
        Fetches official Cloudflare IPv4 and IPv6 CIDRs from cloudflare.com.
        Falls back to verified built-in ranges if requests fail.
        """
        if self._cached_ipv4 and self._cached_ipv6:
            return self._cached_ipv4, self._cached_ipv6

        ipv4_list: list[str] = []
        ipv6_list: list[str] = []

        try:
            async with httpx2.AsyncClient(timeout=6.0) as client:
                r_v4 = await client.get("https://www.cloudflare.com/ips-v4")
                if r_v4.status_code == 200:
                    lines = [line.strip() for line in r_v4.text.splitlines() if line.strip()]
                    if lines:
                        ipv4_list = lines

                r_v6 = await client.get("https://www.cloudflare.com/ips-v6")
                if r_v6.status_code == 200:
                    lines = [line.strip() for line in r_v6.text.splitlines() if line.strip()]
                    if lines:
                        ipv6_list = lines
        except Exception as e:
            logger.warning(f"Failed to fetch live Cloudflare IPs, using fallbacks: {e}")

        if not ipv4_list:
            ipv4_list = list(CLOUDFLARE_IPV4_FALLBACK)
        if not ipv6_list:
            ipv6_list = list(CLOUDFLARE_IPV6_FALLBACK)

        self._cached_ipv4 = ipv4_list
        self._cached_ipv6 = ipv6_list
        return ipv4_list, ipv6_list


cloudflare_manager = CloudflareManager()
