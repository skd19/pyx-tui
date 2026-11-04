"""UFW (Uncomplicated Firewall) management service."""
from __future__ import annotations

import re
from pydantic import BaseModel, Field
from pyx_panel.config import settings
from pyx_panel.core import get_driver
from pyx_panel.services.cloudflare_manager import cloudflare_manager


class UFWRule(BaseModel):
    """Represents a single numbered UFW firewall rule."""
    index: int
    port: str
    proto: str = "tcp"
    to: str = ""
    action: str = "ALLOW IN"
    from_src: str = "Anywhere"
    comment: str = ""
    is_v6: bool = False


class UFWStatus(BaseModel):
    """Overall UFW firewall status and rule list."""
    active: bool = False
    default_incoming: str = "deny"
    default_outgoing: str = "allow"
    rules: list[UFWRule] = Field(default_factory=list)


class AddRuleForm(BaseModel):
    """Input parameters for creating a new firewall rule."""
    port: str
    proto: str = "tcp"  # "tcp", "udp", or "any"
    action: str = "allow"  # "allow" or "deny"
    comment: str = ""


class UFWManager:
    """Manages UFW firewall status, rules, and server hardening safeguards."""

    def __init__(self) -> None:
        self.driver = get_driver()

    async def get_status(self) -> UFWStatus:
        """Retrieves and parses current UFW firewall state."""
        raw = await self.driver.get_ufw_status()
        rules = [
            UFWRule(
                index=r.get("index", idx + 1),
                port=r.get("port", ""),
                proto=r.get("proto", "tcp"),
                to=r.get("to", ""),
                action=r.get("action", "ALLOW IN"),
                from_src=r.get("from", "Anywhere"),
                comment=r.get("comment", ""),
                is_v6=r.get("is_v6", False),
            )
            for idx, r in enumerate(raw.get("rules", []))
        ]
        return UFWStatus(
            active=raw.get("active", False),
            default_incoming=raw.get("default_incoming", "deny"),
            default_outgoing=raw.get("default_outgoing", "allow"),
            rules=rules,
        )

    def validate_port_spec(self, port_str: str) -> tuple[bool, str]:
        """Validates port or port-range specification (e.g. '80', '8000:8010', 'ssh')."""
        clean = port_str.strip()
        if not clean:
            return False, "Port cannot be empty"

        # Check single port or port range
        if ":" in clean:
            parts = clean.split(":")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                p1, p2 = int(parts[0]), int(parts[1])
                if 1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2:
                    return True, clean
                return False, "Invalid port range (must be 1-65535, start <= end)"
            return False, "Invalid port range format (use start:end, e.g. 8000:8010)"

        if clean.isdigit():
            p = int(clean)
            if 1 <= p <= 65535:
                return True, clean
            return False, "Port number must be between 1 and 65535"

        # Service name like 'ssh', 'http', 'https'
        if re.match(r"^[a-zA-Z0-9_\-]+$", clean):
            return True, clean

        return False, "Invalid port specification"

    async def add_rule(self, form: AddRuleForm) -> tuple[bool, str]:
        """Validates input and dispatches allow/deny rule to UFW."""
        valid, val_msg = self.validate_port_spec(form.port)
        if not valid:
            return False, val_msg

        proto = form.proto.strip().lower()
        if proto not in ("tcp", "udp", "any"):
            proto = "tcp"

        action = form.action.strip().lower()
        comment = form.comment.strip()

        if action == "deny":
            return await self.driver.ufw_deny(port=val_msg, proto=proto, comment=comment)
        return await self.driver.ufw_allow(port=val_msg, proto=proto, comment=comment)

    async def delete_rule(self, rule_num: int) -> tuple[bool, str]:
        """Deletes a numbered rule from UFW."""
        if rule_num < 1:
            return False, "Invalid rule index"
        return await self.driver.ufw_delete_rule(rule_num)

    async def is_ssh_allowed(self) -> bool:
        """Checks if SSH (port 22 or ssh service) is currently allowed in active rules."""
        status = await self.get_status()
        for r in status.rules:
            if "ALLOW" in r.action.upper():
                if r.port in ("22", "ssh") or "22" in r.to or "ssh" in r.to:
                    return True
        return False

    async def toggle_ufw(
        self, enable: bool, auto_allow_ssh: bool = True, panel_port: int = 8000
    ) -> tuple[bool, str]:
        """
        Enables or disables UFW with anti-lockout protection.
        Prevents enabling UFW if SSH port 22 is not allowed, unless auto_allow_ssh is True.
        """
        if enable:
            ssh_allowed = await self.is_ssh_allowed()
            if not ssh_allowed:
                if auto_allow_ssh:
                    await self.driver.ufw_allow("22", proto="tcp", comment="SSH Safety Rule")
                else:
                    return (
                        False,
                        "Anti-Lockout Protection: Enabling UFW without allowing SSH (port 22) "
                        "would lock you out of terminal access. Please allow port 22 first.",
                    )

            # Also ensure active panel port is allowed so connection is preserved
            if panel_port > 0:
                await self.driver.ufw_allow(str(panel_port), proto="tcp", comment="pyx-panel Management")

            # Enforce default policies: deny incoming, allow outgoing
            await self.driver.ufw_reset_default_policies()

        return await self.driver.ufw_set_enabled(enable)

    async def apply_baseline_security(self, panel_port: int = 8000) -> tuple[bool, str]:
        """
        Configures recommended server baseline:
        - Default deny incoming, default allow outgoing
        - Allow SSH (22/tcp)
        - Allow HTTP (80/tcp)
        - Allow HTTPS (443/tcp)
        - Allow pyx-panel port
        - Enable UFW
        """
        await self.driver.ufw_reset_default_policies()

        # Add essential rules
        await self.driver.ufw_allow("22", proto="tcp", comment="SSH Remote Access")
        await self.driver.ufw_allow("80", proto="tcp", comment="HTTP Web Traffic")
        await self.driver.ufw_allow("443", proto="tcp", comment="HTTPS Web Traffic")

        if panel_port > 0:
            await self.driver.ufw_allow(str(panel_port), proto="tcp", comment="pyx-panel Management")

        # Enable UFW
        success, msg = await self.driver.ufw_set_enabled(True)
        if not success:
            return False, f"Failed to enable UFW: {msg}"

        return True, "Security baseline applied: SSH (22), HTTP (80), HTTPS (443), and panel port open with default deny incoming"

    async def is_cloudflare_shield_active(self) -> bool:
        """Checks if Cloudflare-specific rules are active on ports 80/443."""
        status = await self.get_status()
        cf_rules = [r for r in status.rules if "cloudflare" in r.comment.lower() or "cloudflare" in r.from_src.lower()]
        # If we have Cloudflare rules and no generic open 80/tcp from anywhere
        has_generic_80 = any(
            r.action.startswith("ALLOW") and r.port in ("80", "80/tcp") and ("Anywhere" in r.from_src)
            for r in status.rules
        )
        return len(cf_rules) > 0 and not has_generic_80

    async def apply_cloudflare_shield(
        self, panel_port: int = 8000, block_app_port: str = "8080"
    ) -> tuple[bool, str]:
        """
        Restricts ports 80 and 443 exclusively to Cloudflare published IP ranges.
        Optionally blocks public access to backend app port (e.g. 8080).
        Preserves SSH (22) and panel port access.
        """
        # 1. Reset default policies: deny incoming, allow outgoing
        await self.driver.ufw_reset_default_policies()

        # 2. Ensure SSH is allowed
        await self.driver.ufw_allow("22", proto="tcp", comment="SSH Remote Access")

        # 3. Ensure pyx-panel port is allowed
        if panel_port > 0:
            await self.driver.ufw_allow(str(panel_port), proto="tcp", comment="pyx-panel Management")

        # 4. If backend app port specified, block public external access
        if block_app_port.strip():
            valid_p, clean_p = self.validate_port_spec(block_app_port.strip())
            if valid_p:
                await self.driver.ufw_deny(clean_p, proto="tcp", comment="Block Direct App Access")

        # 5. Fetch Cloudflare IPv4 & IPv6 CIDRs
        v4_ranges, v6_ranges = await cloudflare_manager.get_cloudflare_ips()

        for ip in v4_ranges:
            await self.driver.ufw_allow_from(ip, port="80", proto="tcp", comment="Cloudflare IPv4")
            await self.driver.ufw_allow_from(ip, port="443", proto="tcp", comment="Cloudflare IPv4")

        for ip in v6_ranges:
            await self.driver.ufw_allow_from(ip, port="80", proto="tcp", comment="Cloudflare IPv6")
            await self.driver.ufw_allow_from(ip, port="443", proto="tcp", comment="Cloudflare IPv6")

        # 6. Delete unrestricted 80/tcp and 443/tcp rules from Anywhere
        await self.driver.ufw_delete_rule_by_spec(["allow", "80/tcp"])
        await self.driver.ufw_delete_rule_by_spec(["allow", "443/tcp"])
        await self.driver.ufw_delete_rule_by_spec(["allow", "80"])
        await self.driver.ufw_delete_rule_by_spec(["allow", "443"])

        # 7. Enable UFW
        success, msg = await self.driver.ufw_set_enabled(True)
        if not success:
            return False, f"Failed to enable UFW: {msg}"

        total_ranges = len(v4_ranges) + len(v6_ranges)
        return True, f"Cloudflare Web Shield active: ports 80/443 restricted to {total_ranges} Cloudflare IP ranges. Public access to app port {block_app_port} blocked."

    async def revert_cloudflare_shield(self, panel_port: int = 8000) -> tuple[bool, str]:
        """
        Reverts Cloudflare-only rules, restoring standard public HTTP (80) and HTTPS (443) rules.
        """
        # 1. Allow public 80 and 443
        await self.driver.ufw_allow("80", proto="tcp", comment="HTTP Web Traffic")
        await self.driver.ufw_allow("443", proto="tcp", comment="HTTPS Web Traffic")

        # 2. Remove Cloudflare-specific rules
        status = await self.get_status()
        cf_indices = [
            r.index for r in status.rules
            if "cloudflare" in r.comment.lower() or "cloudflare" in r.from_src.lower()
        ]
        # Delete from highest index to lowest to preserve numbering
        for idx in sorted(cf_indices, reverse=True):
            await self.driver.ufw_delete_rule(idx)

        return True, "Reverted Cloudflare Web Shield: ports 80 and 443 are now open to all incoming traffic"

    async def open_panel_port(self, panel_port: int) -> tuple[bool, str]:
        """
        Ensures the panel's management port is open on UFW when active.
        Called on server startup so the web UI is immediately accessible.
        """
        if panel_port <= 0:
            return True, "Panel port disabled"

        status = await self.get_status()
        if not status.active:
            return True, "UFW is inactive; panel port accessible by default"

        port_str = str(panel_port)
        already_open = any(
            (r.port == port_str or r.port == f"{port_str}/tcp") and r.action.startswith("ALLOW")
            for r in status.rules
        )
        if not already_open:
            await self.driver.ufw_allow(port_str, proto="tcp", comment="pyx-panel Ephemeral Port")
            return True, f"Opened ephemeral firewall port {panel_port}/tcp in UFW"

        return True, f"Firewall port {panel_port}/tcp already allowed in UFW"

    async def close_panel_port(self, panel_port: int) -> tuple[bool, str]:
        """
        Closes/deletes the panel's management port rule from UFW upon shutdown.
        Leaves no open management ports exposed when pyx-panel is stopped.
        """
        if panel_port <= 0:
            return True, "Panel port disabled"

        status = await self.get_status()
        if not status.active:
            return True, "UFW is inactive; no firewall rules to clean up"

        port_str = str(panel_port)
        # 1. Delete by spec
        await self.driver.ufw_delete_rule_by_spec(["allow", f"{port_str}/tcp"])
        await self.driver.ufw_delete_rule_by_spec(["allow", port_str])

        # 2. Check remaining rules and delete any leftover matches by index (reverse order)
        status_updated = await self.get_status()
        matching_rules = [
            r for r in status_updated.rules
            if (r.port == port_str or r.port == f"{port_str}/tcp" or "pyx-panel" in r.comment.lower())
            and r.action.startswith("ALLOW")
        ]
        for rule in sorted(matching_rules, key=lambda x: x.index, reverse=True):
            await self.driver.ufw_delete_rule(rule.index)

        return True, f"Closed ephemeral firewall port {panel_port}/tcp in UFW"


ufw_manager = UFWManager()
