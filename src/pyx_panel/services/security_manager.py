"""VPS Security Hardening, Audit, and Threat Mitigation Manager."""
from __future__ import annotations

import datetime
from pydantic import BaseModel, Field

from pyx_panel.config import settings
from pyx_panel.core import get_driver
from pyx_panel.services.cloudflare_manager import cloudflare_manager
from pyx_panel.services.nginx_manager import nginx_manager
from pyx_panel.services.ufw_manager import ufw_manager


class SecurityCheckItem(BaseModel):
    """Represents a single automated security audit check."""
    id: str
    category: str  # "Firewall", "SSH", "Nginx", "Network", "Exposure"
    title: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    status: str  # "PASS", "WARN", "FAIL"
    remediation_action: str | None = None
    remediation_label: str | None = None
    details: str = ""


class SecurityAuditReport(BaseModel):
    """Complete security audit report with score, grade, and actionable items."""
    score: int
    score_grade: str  # "A+", "A", "B", "C", "F"
    timestamp: str
    checks: list[SecurityCheckItem] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    listening_ports: list[dict] = Field(default_factory=list)


SENSITIVE_PORTS = {"3306", "5432", "6379", "27017", "8080", "9000", "3000", "5000", "8081"}


class SecurityManager:
    """Orchestrates security audits, vulnerability detection, and automated VPS hardening."""

    def __init__(self) -> None:
        self.driver = get_driver()
        self.ufw_mgr = ufw_manager
        self.nginx_mgr = nginx_manager

    async def run_security_audit(self) -> SecurityAuditReport:
        """Runs comprehensive automated checks across Firewall, SSH, Nginx, Ports, and Kernel."""
        checks: list[SecurityCheckItem] = []

        # 1. Audit UFW Firewall status & default policy
        ufw_status = await self.ufw_mgr.get_status()
        if not ufw_status.active:
            checks.append(SecurityCheckItem(
                id="ufw_status",
                category="Firewall",
                title="UFW Firewall Status",
                description="Firewall must be active to protect unproxied internal services.",
                severity="CRITICAL",
                status="FAIL",
                remediation_action="enable_ufw",
                remediation_label="Enable UFW Firewall",
                details="UFW is INACTIVE! All listening ports on your VPS are exposed to the open internet.",
            ))
        elif ufw_status.default_incoming != "deny":
            checks.append(SecurityCheckItem(
                id="ufw_status",
                category="Firewall",
                title="UFW Default Incoming Policy",
                description="Default incoming traffic policy should be 'deny'.",
                severity="HIGH",
                status="WARN",
                remediation_action="ufw_default_deny",
                remediation_label="Set Default Deny Incoming",
                details=f"UFW is active, but incoming default policy is '{ufw_status.default_incoming}' instead of 'deny'.",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="ufw_status",
                category="Firewall",
                title="UFW Firewall & Default Policy",
                description="Firewall active with incoming default deny policy.",
                severity="LOW",
                status="PASS",
                details="UFW is active with incoming traffic blocked by default.",
            ))

        # 2. Audit SSH Password Authentication
        ssh_cfg = await self.driver.read_ssh_config()
        has_keys = await self.driver.has_ssh_authorized_keys()
        if ssh_cfg.get("password_authentication", True):
            checks.append(SecurityCheckItem(
                id="ssh_password_auth",
                category="SSH",
                title="SSH Password Authentication",
                description="Password authentication allows automated botnet brute-force attacks.",
                severity="CRITICAL",
                status="FAIL",
                remediation_action="ssh_keys_only" if has_keys else None,
                remediation_label="Enforce SSH Keys Only" if has_keys else "Add SSH Key First (Anti-Lockout)",
                details="Password authentication is ENABLED. VPS is actively vulnerable to credential brute-forcing." + (
                    " (Authorized SSH keys detected; safe to disable passwords)." if has_keys else " (No authorized keys found. Add an SSH public key before disabling passwords to prevent lockout!)"
                ),
            ))
        else:
            checks.append(SecurityCheckItem(
                id="ssh_password_auth",
                category="SSH",
                title="SSH Password Authentication",
                description="SSH passwords disabled; key-based authentication only.",
                severity="LOW",
                status="PASS",
                details="Password authentication is DISABLED. Only cryptographic public/private keys are accepted.",
            ))

        # 3. Audit SSH Root Login
        root_login = str(ssh_cfg.get("permit_root_login", "prohibit-password")).lower()
        if root_login in ("yes", "true", "1"):
            checks.append(SecurityCheckItem(
                id="ssh_root_login",
                category="SSH",
                title="SSH Direct Root Login",
                description="Attackers continually target the 'root' username with brute force.",
                severity="HIGH",
                status="WARN",
                remediation_action="ssh_restrict_root",
                remediation_label="Restrict Direct Root Login",
                details="Direct SSH root login with password is permitted.",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="ssh_root_login",
                category="SSH",
                title="SSH Direct Root Login",
                description="Direct SSH root login is restricted or prohibited.",
                severity="LOW",
                status="PASS",
                details=f"Direct SSH root login is restricted ({root_login}).",
            ))

        # 4. Audit Nginx Direct IP Drop (Default Deny Catch-all)
        is_drop = self.nginx_mgr.is_default_deny_active()
        if is_drop:
            checks.append(SecurityCheckItem(
                id="direct_ip_drop",
                category="Nginx",
                title="Direct IP Drop (Default-Deny Catch-All)",
                description="Rejects raw IP scans and unknown hostnames with HTTP 444 / SSL handshake reject.",
                severity="LOW",
                status="PASS",
                details="Catch-all default_server is active. Direct IP requests and automated scanners are immediately dropped.",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="direct_ip_drop",
                category="Nginx",
                title="Direct IP Drop (Default-Deny Catch-All)",
                description="Without catch-all, attackers scanning your VPS IP address directly can discover hosted sites.",
                severity="HIGH",
                status="WARN",
                remediation_action="enable_default_deny",
                remediation_label="Enable Direct IP Drop (444)",
                details="Direct IP access is not dropped. Shodan/Censys scanners can map your origin IP directly.",
            ))

        # 5. Audit Nginx Global Security Guard (Tokens, Rate Limiting, Slowloris)
        is_guard = self.nginx_mgr.is_security_guard_active()
        if is_guard:
            checks.append(SecurityCheckItem(
                id="nginx_security_guard",
                category="Nginx",
                title="Nginx Global Security Guard",
                description="Hides server version tokens, establishes rate-limit zones, and sets Slowloris timeouts.",
                severity="LOW",
                status="PASS",
                details="Security guard active in conf.d: server_tokens off, rate-limiting zones, and connection timeouts configured.",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="nginx_security_guard",
                category="Nginx",
                title="Nginx Global Security Guard",
                description="Enforces server_tokens off, rate limiting zones, and client request timeouts.",
                severity="MEDIUM",
                status="WARN",
                remediation_action="enable_nginx_guard",
                remediation_label="Enable Nginx Security Guard",
                details="Security guard is inactive. Web server version signature is visible and connection timeouts are not hardened against Slowloris.",
            ))

        # 6. Audit Cloudflare Web Shield
        is_cf = await self.ufw_mgr.is_cloudflare_shield_active()
        if is_cf:
            checks.append(SecurityCheckItem(
                id="cloudflare_shield",
                category="Firewall",
                title="Cloudflare Web Shield",
                description="Restricts web ports 80/443 exclusively to Cloudflare edge proxy IP ranges.",
                severity="LOW",
                status="PASS",
                details="Ports 80 and 443 are locked down to official Cloudflare edge IP ranges. Direct bypass blocked.",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="cloudflare_shield",
                category="Firewall",
                title="Cloudflare Web Shield",
                description="Locks down web ports 80 and 443 strictly to Cloudflare proxy IP ranges.",
                severity="MEDIUM",
                status="WARN",
                remediation_action="enable_cloudflare_shield",
                remediation_label="Activate Cloudflare Shield",
                details="Ports 80/443 are open to all IP addresses worldwide. If using Cloudflare proxy, direct origin IP access is not restricted.",
            ))

        # 7. Audit Kernel SYN Cookies
        syn_val = await self.driver.read_sysctl_setting("net.ipv4.tcp_syncookies")
        if syn_val.strip() == "1":
            checks.append(SecurityCheckItem(
                id="kernel_syn_cookies",
                category="Network",
                title="TCP SYN Flood Mitigation",
                description="Kernel TCP SYN cookies prevent connection queue exhaustion during DoS attacks.",
                severity="LOW",
                status="PASS",
                details="TCP SYN cookies enabled (net.ipv4.tcp_syncookies=1).",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="kernel_syn_cookies",
                category="Network",
                title="TCP SYN Flood Mitigation",
                description="Protects against SYN flood denial of service attacks.",
                severity="MEDIUM",
                status="WARN",
                remediation_action="harden_kernel_sysctl",
                remediation_label="Apply Kernel Hardening",
                details="TCP SYN cookies are disabled. Host kernel is vulnerable to SYN flood connection exhaustion.",
            ))

        # 8. Audit Reverse Path Filtering (Anti-Spoofing)
        rp_val = await self.driver.read_sysctl_setting("net.ipv4.conf.all.rp_filter")
        if rp_val.strip() == "1":
            checks.append(SecurityCheckItem(
                id="kernel_anti_spoofing",
                category="Network",
                title="Kernel Anti-Spoofing (rp_filter)",
                description="Reverse Path Filtering prevents IP source address spoofing.",
                severity="LOW",
                status="PASS",
                details="Reverse Path Filtering is enabled (net.ipv4.conf.all.rp_filter=1).",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="kernel_anti_spoofing",
                category="Network",
                title="Kernel Anti-Spoofing (rp_filter)",
                description="Validates packets have legitimate source IP addresses according to routing tables.",
                severity="LOW",
                status="WARN",
                remediation_action="harden_kernel_sysctl",
                remediation_label="Apply Kernel Hardening",
                details="Reverse Path Filtering is disabled. Packet source IP spoofing is possible.",
            ))

        # 9. Audit Listening Ports for Public Exposure of Sensitive Services
        listening = await self.driver.get_listening_ports()
        exposed_items = []
        panel_port_str = str(settings.panel_port)
        safe_public_ports = {"22", "80", "443", panel_port_str}

        for sock in listening:
            port = sock.get("port", "")
            is_loopback = sock.get("is_loopback", False)
            if not is_loopback:
                if port in SENSITIVE_PORTS or (sock.get("is_public", False) and port not in safe_public_ports):
                    exposed_items.append(sock)

        if exposed_items:
            exp_summary = ", ".join(f"{s['port']}/tcp ({s['process']})" for s in exposed_items)
            checks.append(SecurityCheckItem(
                id="exposed_internal_ports",
                category="Exposure",
                title="Sensitive Internal Services Exposure",
                description="Internal application ports and databases must not listen directly on 0.0.0.0.",
                severity="CRITICAL",
                status="FAIL",
                remediation_action="isolate_exposed_ports",
                remediation_label="Isolate Port(s) with UFW",
                details=f"Discovered {len(exposed_items)} service(s) listening publicly on 0.0.0.0 instead of 127.0.0.1: {exp_summary}. Direct access bypasses Nginx and exposes backend directly.",
            ))
        else:
            checks.append(SecurityCheckItem(
                id="exposed_internal_ports",
                category="Exposure",
                title="Sensitive Internal Services Exposure",
                description="Internal backend apps and databases listening on localhost (127.0.0.1) only.",
                severity="LOW",
                status="PASS",
                details="No unshielded internal application ports or databases detected on public interfaces.",
            ))

        # Calculate Score (0-100) and Grade
        weights = {
            "ufw_status": 15,
            "ssh_password_auth": 20,
            "ssh_root_login": 10,
            "direct_ip_drop": 15,
            "nginx_security_guard": 10,
            "cloudflare_shield": 10,
            "kernel_syn_cookies": 5,
            "kernel_anti_spoofing": 5,
            "exposed_internal_ports": 10,
        }

        score = 0
        passed_cnt = 0
        warn_cnt = 0
        fail_cnt = 0

        for chk in checks:
            w = weights.get(chk.id, 5)
            if chk.status == "PASS":
                score += w
                passed_cnt += 1
            elif chk.status == "WARN":
                score += int(w * 0.4)
                warn_cnt += 1
            else:
                fail_cnt += 1

        score = max(0, min(100, score))
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        else:
            grade = "F"

        report = SecurityAuditReport(
            score=score,
            score_grade=grade,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            checks=checks,
            stats={
                "total": len(checks),
                "passed": passed_cnt,
                "warnings": warn_cnt,
                "failed": fail_cnt,
            },
            listening_ports=listening,
        )
        return report

    async def harden_ssh_keys_only(self) -> tuple[bool, str]:
        """
        Hardens SSH by enforcing keys-only authentication (PasswordAuthentication no).
        Guarded by anti-lockout check: verifies authorized keys exist before disabling passwords.
        """
        has_keys = await self.driver.has_ssh_authorized_keys()
        if not has_keys:
            return (
                False,
                "Anti-Lockout Protection: No SSH authorized keys found for root/admin user. "
                "You must install an SSH public key before disabling password authentication.",
            )

        return await self.driver.write_ssh_hardening(
            disable_password_auth=True,
            disable_root_login=False,
        )

    async def restrict_ssh_root(self) -> tuple[bool, str]:
        """Restricts direct SSH root login (PermitRootLogin prohibit-password)."""
        return await self.driver.write_ssh_hardening(
            disable_password_auth=False,
            disable_root_login=True,
        )

    async def harden_ssh_full(self) -> tuple[bool, str]:
        """Hardens SSH completely: keys-only auth and restricted root login."""
        has_keys = await self.driver.has_ssh_authorized_keys()
        if not has_keys:
            return (
                False,
                "Anti-Lockout Protection: No SSH authorized keys found for root/admin user. "
                "You must install an SSH public key before disabling password authentication.",
            )

        return await self.driver.write_ssh_hardening(
            disable_password_auth=True,
            disable_root_login=True,
        )

    async def apply_kernel_hardening(self) -> tuple[bool, str]:
        """Applies Linux kernel network parameters via sysctl."""
        settings_to_apply = {
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.default.rp_filter": "1",
            "net.ipv4.conf.all.accept_source_route": "0",
            "net.ipv4.conf.default.accept_source_route": "0",
            "net.ipv6.conf.all.accept_source_route": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.default.send_redirects": "0",
        }
        return await self.driver.apply_sysctl_settings(settings_to_apply)

    async def isolate_port_ufw(self, port: str, proto: str = "tcp") -> tuple[bool, str]:
        """Adds a UFW deny rule to isolate an internal application or database port."""
        clean_port = port.strip()
        if not clean_port:
            return False, "Port number cannot be empty"
        return await self.driver.ufw_deny(clean_port, proto=proto, comment="Pyx Internal App Isolation")

    async def harden_all(self) -> dict[str, tuple[bool, str]]:
        """
        Executes a 1-click comprehensive hardening sequence:
        1. UFW Baseline (SSH + Web + Panel allowed, default deny incoming)
        2. Nginx Security Guard (Hide server tokens, rate limiting zones, Slowloris timeouts)
        3. Direct IP Drop (Catch-all 444 / SSL reject)
        4. Kernel Hardening (SYN cookies, anti-spoofing)
        5. SSH Hardening (Keys-only & restricted root, if authorized keys exist)
        """
        results: dict[str, tuple[bool, str]] = {}

        # 1. UFW baseline
        results["ufw"] = await self.ufw_mgr.apply_baseline_security(panel_port=settings.panel_port)

        # 2. Nginx Security Guard
        results["nginx_guard"] = await self.nginx_mgr.apply_security_guard()

        # 3. Direct IP Drop
        results["direct_ip_drop"] = await self.nginx_mgr.enable_default_deny()

        # 4. Kernel Hardening
        results["kernel"] = await self.apply_kernel_hardening()

        # 5. SSH Hardening (with anti-lockout verification)
        has_keys = await self.driver.has_ssh_authorized_keys()
        if has_keys:
            results["ssh"] = await self.harden_ssh_full()
        else:
            results["ssh"] = (
                False,
                "SSH password hardening skipped: No authorized keys found in /root/.ssh/authorized_keys (Anti-Lockout Protection)",
            )

        return results


security_manager = SecurityManager()
