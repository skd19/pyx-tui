"""UFW (Uncomplicated Firewall) management service."""
from __future__ import annotations

import re
from pydantic import BaseModel, Field
from pyx_panel.config import settings
from pyx_panel.core import get_driver


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


ufw_manager = UFWManager()
