"""Certbot and SSL certificate manager with DNS pre-checks."""
from __future__ import annotations

import re
import socket
import httpx2
from pydantic import BaseModel, Field
from pyx_panel.core import get_driver
from pyx_panel.services.nginx_manager import nginx_manager, parse_domain_and_www_alias


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

    async def remove_certificate(self, cert_name_or_domain: str) -> tuple[bool, str]:
        """
        Removes an SSL certificate:
        1. Identifies the certificate name and associated domains.
        2. Locates any Nginx virtual hosts configured with this certificate/domain.
        3. Strips SSL directives from those virtual hosts, reverting them to HTTP.
        4. Validates Nginx configuration syntax.
        5. Deletes the certificate from Certbot using 'certbot delete'.
        6. Reloads Nginx.
        """
        target = cert_name_or_domain.strip()
        if not target:
            return False, "No certificate or domain specified."

        # 1. Look up certificate in certbot list
        certs = await self.list_certificates()
        matched_cert = next(
            (c for c in certs if c.get("name") == target or target in c.get("domains", [])),
            None,
        )
        cert_name = matched_cert["name"] if matched_cert else target

        # 2. Find matching sites
        matching_sites = nginx_manager.find_sites_for_domain_or_cert(cert_name)
        if matched_cert:
            for d in matched_cert.get("domains", []):
                for s in nginx_manager.find_sites_for_domain_or_cert(d):
                    if s.name not in [ms.name for ms in matching_sites]:
                        matching_sites.append(s)

        # 3. For each site with SSL enabled, remove SSL with rollback capability
        reverted_sites: list[tuple[str, str, bool]] = []
        for s in matching_sites:
            if s.ssl_enabled:
                available_path = nginx_manager.available_dir / s.filename
                enabled_path = nginx_manager.enabled_dir / s.filename
                orig = self.driver.read_file(available_path)
                cleaned = nginx_manager.remove_ssl_from_config(orig)
                reverted_sites.append((s.name, orig, s.enabled))
                self.driver.write_file(available_path, cleaned)
                if s.enabled:
                    self.driver.write_file(enabled_path, cleaned)

        # 4. Test Nginx syntax
        is_valid, msg = await self.driver.test_nginx()
        if not is_valid:
            # Atomic rollback
            for s_name, orig, is_en in reverted_sites:
                fn = nginx_manager._sanitize_name(s_name)
                self.driver.write_file(nginx_manager.available_dir / fn, orig)
                if is_en:
                    self.driver.write_file(nginx_manager.enabled_dir / fn, orig)
            return False, f"Cannot remove SSL: Nginx syntax test failed: {msg}"

        # 5. Delete certificate from Certbot
        del_ok, del_msg = await self.driver.delete_certificate(cert_name)

        # 6. Reload Nginx
        await self.driver.reload_nginx()

        site_names = [s[0] for s in reverted_sites]
        sites_info = f" (reverted sites: {', '.join(site_names)})" if site_names else ""
        if not del_ok and matched_cert:
            return True, f"Nginx sites reverted to HTTP, but Certbot delete noted: {del_msg}"

        return True, f"SSL certificate '{cert_name}' removed successfully{sites_info}. Site is now on HTTP."


certbot_manager = CertbotManager()
