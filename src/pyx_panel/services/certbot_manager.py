"""Certbot and SSL certificate manager with DNS pre-checks."""
from __future__ import annotations

import socket
import httpx2
from pydantic import BaseModel
from pyx_panel.core import get_driver


class DNSCheckResult(BaseModel):
    """Result of checking domain DNS against public VPS IP."""
    domain: str
    vps_ip: str
    domain_ips: list[str]
    matches: bool
    error: str = ""


class CertbotManager:
    """Manages SSL certificate issuance, renewal checks, and DNS pre-checks."""

    def __init__(self) -> None:
        self.driver = get_driver()
        self._cached_vps_ip: str = ""

    async def get_public_ip(self) -> str:
        """Fetches the public IP address of the VPS using httpx2."""
        if self._cached_vps_ip:
            return self._cached_vps_ip

        endpoints = [
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/all.json",
        ]

        async with httpx2.AsyncClient(timeout=5.0) as client:
            for url in endpoints:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        ip = data.get("ip") or data.get("ip_addr")
                        if ip:
                            self._cached_vps_ip = ip.strip()
                            return self._cached_vps_ip
                except Exception:
                    continue

        # Fallback to local socket trick if external fails
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self._cached_vps_ip = s.getsockname()[0]
            s.close()
            return self._cached_vps_ip
        except Exception:
            return "127.0.0.1"

    async def check_domain_dns(self, domain: str) -> DNSCheckResult:
        """Verifies if the domain's DNS A/AAAA records point to this VPS."""
        clean_domain = domain.strip().lower()
        vps_ip = await self.get_public_ip()
        domain_ips: list[str] = []

        try:
            addr_info = socket.getaddrinfo(clean_domain, 80, socket.AF_INET)
            for item in addr_info:
                ip = item[4][0]
                if ip not in domain_ips:
                    domain_ips.append(ip)
        except socket.gaierror as e:
            return DNSCheckResult(
                domain=clean_domain,
                vps_ip=vps_ip,
                domain_ips=[],
                matches=False,
                error=f"DNS resolution failed: {e}",
            )
        except Exception as e:
            return DNSCheckResult(
                domain=clean_domain,
                vps_ip=vps_ip,
                domain_ips=[],
                matches=False,
                error=str(e),
            )

        matches = (vps_ip in domain_ips) or (vps_ip.startswith("127.") and "127.0.0.1" in domain_ips)
        return DNSCheckResult(
            domain=clean_domain,
            vps_ip=vps_ip,
            domain_ips=domain_ips,
            matches=matches,
        )

    async def provision_certificate(
        self, domain: str, email: str = "", force: bool = False
    ) -> tuple[bool, str]:
        """
        Runs DNS pre-check and issues SSL certificate via Certbot.
        """
        clean_domain = domain.strip().lower()

        if not force:
            dns_res = await self.check_domain_dns(clean_domain)
            if not dns_res.matches:
                ips_str = ", ".join(dns_res.domain_ips) if dns_res.domain_ips else "none"
                return (
                    False,
                    f"DNS pre-check failed: {clean_domain} resolves to [{ips_str}], "
                    f"but VPS IP is {dns_res.vps_ip}. "
                    f"Please point your domain A-record to {dns_res.vps_ip} first.",
                )

        return await self.driver.run_certbot(clean_domain, email)

    async def list_certificates(self) -> list[dict]:
        """Returns list of currently installed certificates."""
        return await self.driver.list_certificates()


certbot_manager = CertbotManager()
