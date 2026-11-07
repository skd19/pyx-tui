"""Certbot and SSL certificate manager with DNS pre-checks."""
from __future__ import annotations

import re
import socket
import httpx2
from pydantic import BaseModel, Field
from pyx_panel.core import get_driver
from pyx_panel.services.nginx_manager import parse_domain_and_www_alias


class DNSCheckResult(BaseModel):
    """Result of checking domain DNS against public VPS IP."""
    domain: str
    vps_ip: str
    domain_ips: list[str]
    matches: bool
    error: str = ""
    details: dict[str, dict] = Field(default_factory=dict)


class CertbotManager:
    """Manages SSL certificate issuance, renewal checks, and DNS pre-checks."""

    def __init__(self) -> None:
        self.driver = get_driver()
        self._cached_vps_ip: str = ""

    def normalize_domain_list(
        self,
        domain_or_domains: str | list[str],
        include_www: bool = False,
    ) -> list[str]:
        """
        Parses domain string or list into a deduplicated list of domains.
        If include_www is True, automatically includes both apex and www alias for eligible domains.
        """
        if isinstance(domain_or_domains, str):
            raw = [d.strip().lower() for d in re.split(r"[\s,]+", domain_or_domains) if d.strip()]
        else:
            raw = [d.strip().lower() for d in domain_or_domains if d.strip()]

        result: list[str] = []
        for d in raw:
            if include_www:
                root_dom, www_dom = parse_domain_and_www_alias(d)
                if root_dom and root_dom not in result:
                    result.append(root_dom)
                if www_dom and www_dom not in result:
                    result.append(www_dom)
                if not root_dom and not www_dom and d not in result:
                    result.append(d)
            else:
                if d not in result:
                    result.append(d)

        return result

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

    async def check_domain_dns(
        self,
        domain_or_domains: str | list[str],
        include_www: bool = False,
    ) -> DNSCheckResult:
        """Verifies if the domain(s) DNS A/AAAA records point to this VPS."""
        domains = self.normalize_domain_list(domain_or_domains, include_www=include_www)
        if not domains:
            return DNSCheckResult(
                domain="",
                vps_ip="",
                domain_ips=[],
                matches=False,
                error="No valid domains provided for DNS check",
            )

        vps_ip = await self.get_public_ip()
        all_domain_ips: list[str] = []
        details: dict[str, dict] = {}
        all_match = True
        failed_domains: list[str] = []

        for d in domains:
            d_ips: list[str] = []
            err = ""
            try:
                addr_info = socket.getaddrinfo(d, 80, socket.AF_INET)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in d_ips:
                        d_ips.append(ip)
                    if ip not in all_domain_ips:
                        all_domain_ips.append(ip)
            except socket.gaierror as e:
                err = f"DNS resolution failed: {e}"
            except Exception as e:
                err = str(e)

            is_match = bool(d_ips) and (
                (vps_ip in d_ips)
                or (vps_ip.startswith("127.") and "127.0.0.1" in d_ips)
            )

            if not is_match:
                all_match = False
                res_info = f"resolves to [{', '.join(d_ips)}]" if d_ips else "no A-record"
                failed_domains.append(f"'{d}' ({err or res_info})")

            details[d] = {
                "ips": d_ips,
                "matches": is_match,
                "error": err,
            }

        domain_summary = ", ".join(domains)
        err_msg = ""
        if not all_match:
            err_msg = (
                f"DNS pre-check failed: {'; '.join(failed_domains)}. "
                f"VPS IP is {vps_ip}. Please point domain A-record(s) to {vps_ip} first."
            )

        return DNSCheckResult(
            domain=domain_summary,
            vps_ip=vps_ip,
            domain_ips=all_domain_ips,
            matches=all_match,
            error=err_msg,
            details=details,
        )

    async def provision_certificate(
        self,
        domain: str | list[str],
        email: str = "",
        force: bool = False,
        include_www: bool = False,
    ) -> tuple[bool, str]:
        """
        Runs DNS pre-check and issues SSL certificate via Certbot for one or more domains.
        """
        domain_list = self.normalize_domain_list(domain, include_www=include_www)
        if not domain_list:
            return False, "No valid domain specified for SSL certificate provisioning."

        if not force:
            dns_res = await self.check_domain_dns(domain_list, include_www=False)
            if not dns_res.matches:
                return False, dns_res.error

        return await self.driver.run_certbot(domain_list, email)

    async def list_certificates(self) -> list[dict]:
        """Returns list of currently installed certificates."""
        return await self.driver.list_certificates()


certbot_manager = CertbotManager()
