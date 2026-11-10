"""WireGuard VPN service and client management."""
from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path
from pydantic import BaseModel, Field

from pyx_panel.config import settings
from pyx_panel.core import get_driver


class WireGuardPeer(BaseModel):
    """Represents a WireGuard VPN client peer."""
    name: str
    public_key: str
    private_key: str = ""  # Client's private key stored locally for QR and .conf generation
    preshared_key: str = ""
    client_ip: str = "10.8.0.2"
    allowed_ips: str = "10.8.0.2/32"
    tunnel_mode: str = "full"  # "full" (0.0.0.0/0, ::/0) or "split" (10.8.0.0/24)
    dns: str = "1.1.1.1, 1.0.0.1"
    enabled: bool = True
    created_at: str = ""
    latest_handshake: int = 0
    latest_handshake_human: str = "Never"
    transfer_rx: int = 0
    transfer_tx: int = 0
    transfer_total_human: str = "0 B"
    endpoint: str = ""


class WireGuardServerStatus(BaseModel):
    """WireGuard server daemon and firewall status."""
    installed: bool = False
    configured: bool = False
    running: bool = False
    interface: str = "wg0"
    listen_port: int = 51820
    firewall_port_open: bool = False
    public_key: str = ""
    server_ip: str = ""
    network_interface: str = "eth0"
    subnet: str = "10.8.0.1/24"
    dns: str = "1.1.1.1, 1.0.0.1"
    peers_count: int = 0
    active_peers_count: int = 0
    total_rx: int = 0
    total_tx: int = 0
    total_transfer_human: str = "0 B"


class WireGuardSetupForm(BaseModel):
    """Input parameters for server auto-configuration."""
    server_port: int = 51820
    server_ip: str = ""
    subnet: str = "10.8.0.1/24"
    dns: str = "1.1.1.1, 1.0.0.1"
    network_interface: str = ""


class WireGuardPeerForm(BaseModel):
    """Input parameters for creating a new client peer."""
    name: str
    use_psk: bool = True
    tunnel_mode: str = "full"  # "full" or "split"
    dns: str = "1.1.1.1, 1.0.0.1"


class WireGuardSettingsForm(BaseModel):
    """Input parameters for modifying server settings."""
    server_port: int = 51820
    server_ip: str = ""
    dns: str = "1.1.1.1, 1.0.0.1"


def format_bytes(b: int) -> str:
    """Formats raw bytes into human readable format."""
    if b <= 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024.0:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} B"
        b /= 1024.0
    return f"{b:.1f} PB"


def format_handshake(epoch: int) -> str:
    """Formats epoch timestamp into relative time string."""
    if epoch <= 0:
        return "Never"
    diff = int(datetime.datetime.now().timestamp()) - epoch
    if diff < 0:
        return "Just now"
    if diff < 60:
        return f"{diff}s ago"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return f"{diff // 86400}d ago"


class WireGuardManager:
    """Manages WireGuard server, keys, peers, config files, and firewall zero-exposure rules."""

    def __init__(self) -> None:
        self.driver = get_driver()

    @property
    def conf_path(self) -> Path:
        if settings.mock_system:
            return self.driver.wireguard_dir / "wg0.conf"
        return settings.wireguard_conf

    @property
    def meta_path(self) -> Path:
        if settings.mock_system:
            return self.driver.wireguard_dir / "wg0-peers.json"
        return settings.wireguard_dir / "wg0-peers.json"

    def is_configured(self) -> bool:
        """Checks if server configuration file exists."""
        return self.driver.file_exists(self.conf_path)

    def _read_metadata(self) -> dict:
        """Reads peer metadata storage."""
        if not self.driver.file_exists(self.meta_path):
            return {"peers": {}, "server_ip": "", "dns": "1.1.1.1, 1.0.0.1"}
        try:
            raw = self.driver.read_file(self.meta_path)
            return json.loads(raw)
        except Exception:
            return {"peers": {}, "server_ip": "", "dns": "1.1.1.1, 1.0.0.1"}

    def _write_metadata(self, data: dict) -> None:
        """Saves peer metadata atomically."""
        self.driver.write_file(self.meta_path, json.dumps(data, indent=2))

    async def detect_public_ip(self) -> str:
        """Detects the host VPS public IPv4 address."""
        # 1. Check existing metadata
        meta = self._read_metadata()
        if meta.get("server_ip"):
            return meta["server_ip"]

        # 2. Try fetching from external IP API
        try:
            import httpx2
            async with httpx2.AsyncClient(timeout=3.0) as client:
                resp = await client.get("https://api.ipify.org")
                if resp.status_code == 200 and resp.text.strip():
                    ip = resp.text.strip()
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                        return ip
        except Exception:
            pass

        # 3. Fallback
        return "198.51.100.1" if settings.mock_system else "127.0.0.1"

    async def is_firewall_port_open(self, port: int) -> bool:
        """Checks if UDP port is currently allowed in UFW."""
        status = await self.driver.get_ufw_status()
        if not status.get("active", False):
            # If UFW is inactive, port isn't blocked by UFW
            return False
        port_str = str(port)
        for r in status.get("rules", []):
            p = str(r.get("port", ""))
            action = str(r.get("action", ""))
            proto = str(r.get("proto", "")).lower()
            if (p == port_str or p == f"{port_str}/udp") and "allow" in action.lower():
                if proto in ("udp", "any", ""):
                    return True
        return False

    async def get_status(self) -> WireGuardServerStatus:
        """Returns comprehensive server status, port security state, and aggregate stats."""
        raw_status = await self.driver.get_wireguard_status("wg0")
        configured = self.is_configured()
        is_running = raw_status.get("active", False)
        listen_port = raw_port = raw_status.get("listen_port", 51820)
        pub_key = raw_status.get("public_key", "")
        net_iface = await self.driver.get_default_network_interface()

        meta = self._read_metadata()
        server_ip = meta.get("server_ip", "")
        if not server_ip:
            server_ip = await self.detect_public_ip()
        dns = meta.get("dns", "1.1.1.1, 1.0.0.1")

        # Read config to get server info if stopped
        if configured and self.driver.file_exists(self.conf_path):
            conf_text = self.driver.read_file(self.conf_path)
            port_match = re.search(r"^\s*ListenPort\s*=\s*(\d+)", conf_text, re.MULTILINE)
            if port_match:
                listen_port = int(port_match.group(1))

        fw_open = await self.is_firewall_port_open(listen_port)
        peers = await self.list_peers()

        total_rx = sum(p.transfer_rx for p in peers)
        total_tx = sum(p.transfer_tx for p in peers)
        active_peers = sum(1 for p in peers if p.latest_handshake > 0 and (int(datetime.datetime.now().timestamp()) - p.latest_handshake) < 180)

        return WireGuardServerStatus(
            installed=raw_status.get("installed", True),
            configured=configured,
            running=is_running,
            interface="wg0",
            listen_port=listen_port,
            firewall_port_open=fw_open,
            public_key=pub_key,
            server_ip=server_ip,
            network_interface=net_iface,
            subnet="10.8.0.1/24",
            dns=dns,
            peers_count=len(peers),
            active_peers_count=active_peers,
            total_rx=total_rx,
            total_tx=total_tx,
            total_transfer_human=format_bytes(total_rx + total_tx),
        )

    async def setup_server(self, form: WireGuardSetupForm) -> tuple[bool, str]:
        """Auto-configures WireGuard server, generates keys, creates wg0.conf, enables forwarding and starts service."""
        server_priv, server_pub = await self.driver.generate_wireguard_keypair()
        net_iface = form.network_interface.strip() or await self.driver.get_default_network_interface()
        public_ip = form.server_ip.strip() or await self.detect_public_ip()
        port = form.server_port or 51820

        # Construct /etc/wireguard/wg0.conf
        conf_lines = [
            "# Pyx Panel WireGuard Server Configuration",
            "[Interface]",
            f"Address = {form.subnet}",
            f"ListenPort = {port}",
            f"PrivateKey = {server_priv}",
            f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {net_iface} -j MASQUERADE",
            f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {net_iface} -j MASQUERADE",
            "",
        ]

        self.driver.write_file(self.conf_path, "\n".join(conf_lines))

        # Save metadata
        meta = self._read_metadata()
        meta["server_ip"] = public_ip
        meta["server_port"] = port
        meta["server_public_key"] = server_pub
        meta["dns"] = form.dns.strip() or "1.1.1.1, 1.0.0.1"
        self._write_metadata(meta)

        # Enable IPv4 forwarding
        await self.driver.apply_sysctl_settings({"net.ipv4.ip_forward": "1"})

        # Start server and open port
        start_ok, start_msg = await self.start_server()
        if not start_ok:
            return False, f"Server configured, but failed to start: {start_msg}"

        return True, f"WireGuard VPN successfully initialized on port {port}/udp with public IP {public_ip}"

    async def start_server(self) -> tuple[bool, str]:
        """Starts WireGuard service and opens the UFW UDP port."""
        if not self.is_configured():
            return False, "WireGuard is not configured yet. Run setup first."

        # Read listen port from conf
        port = 51820
        if self.driver.file_exists(self.conf_path):
            conf_text = self.driver.read_file(self.conf_path)
            port_match = re.search(r"^\s*ListenPort\s*=\s*(\d+)", conf_text, re.MULTILINE)
            if port_match:
                port = int(port_match.group(1))

        # 1. Enable IPv4 forwarding
        await self.driver.apply_sysctl_settings({"net.ipv4.ip_forward": "1"})

        # 2. Start WireGuard interface
        ok, msg = await self.driver.start_wireguard("wg0")
        if not ok:
            return False, f"Failed to start WireGuard: {msg}"

        # 3. Open UFW UDP port
        await self.driver.ufw_allow(str(port), proto="udp", comment="WireGuard VPN")

        return True, f"WireGuard VPN started and firewall port {port}/udp opened"

    async def stop_server(self) -> tuple[bool, str]:
        """
        Stops WireGuard service and actively blocks/removes the UFW UDP port rule.
        Enforces Zero-Exposure when stopped.
        """
        # Read listen port
        port = 51820
        if self.driver.file_exists(self.conf_path):
            conf_text = self.driver.read_file(self.conf_path)
            port_match = re.search(r"^\s*ListenPort\s*=\s*(\d+)", conf_text, re.MULTILINE)
            if port_match:
                port = int(port_match.group(1))

        # 1. Stop WireGuard interface
        ok, msg = await self.driver.stop_wireguard("wg0")

        # 2. Actively delete and block firewall port (Zero-Exposure)
        port_str = str(port)
        await self.driver.ufw_delete_rule_by_spec(["allow", f"{port_str}/udp"])
        await self.driver.ufw_delete_rule_by_spec(["allow", port_str])

        # Delete any remaining rule with WireGuard comment or matching port
        ufw_status = await self.driver.get_ufw_status()
        matching_rules = [
            r for r in ufw_status.get("rules", [])
            if (str(r.get("port", "")) in (port_str, f"{port_str}/udp") or "wireguard" in str(r.get("comment", "")).lower())
            and "allow" in str(r.get("action", "")).lower()
        ]
        for rule in sorted(matching_rules, key=lambda x: int(x.get("index", 0)), reverse=True):
            await self.driver.ufw_delete_rule(int(rule.get("index", 0)))

        return True, f"WireGuard VPN stopped and port {port}/udp blocked in firewall (Zero Exposure)"

    async def list_peers(self) -> list[WireGuardPeer]:
        """Lists all configured peers, merging live handshake and bandwidth metrics."""
        meta = self._read_metadata()
        peer_meta: dict = meta.get("peers", {})

        raw_status = await self.driver.get_wireguard_status("wg0")
        live_peers = {p["public_key"]: p for p in raw_status.get("peers", [])}

        peers: list[WireGuardPeer] = []
        for name, data in peer_meta.items():
            pub = data.get("public_key", "")
            live = live_peers.get(pub, {})

            handshake = live.get("latest_handshake", 0)
            rx = live.get("transfer_rx", 0)
            tx = live.get("transfer_tx", 0)

            peers.append(WireGuardPeer(
                name=name,
                public_key=pub,
                private_key=data.get("private_key", ""),
                preshared_key=data.get("preshared_key", ""),
                client_ip=data.get("client_ip", "10.8.0.2"),
                allowed_ips=data.get("allowed_ips", "10.8.0.2/32"),
                tunnel_mode=data.get("tunnel_mode", "full"),
                dns=data.get("dns", "1.1.1.1, 1.0.0.1"),
                enabled=data.get("enabled", True),
                created_at=data.get("created_at", ""),
                latest_handshake=handshake,
                latest_handshake_human=format_handshake(handshake),
                transfer_rx=rx,
                transfer_tx=tx,
                transfer_total_human=format_bytes(rx + tx),
                endpoint=live.get("endpoint", ""),
            ))

        return sorted(peers, key=lambda x: x.created_at, reverse=True)

    def _get_next_available_ip(self) -> str:
        """Calculates next unused IP in the 10.8.0.0/24 subnet."""
        meta = self._read_metadata()
        used_octets = {1}  # 1 is reserved for server (10.8.0.1)
        for pdata in meta.get("peers", {}).values():
            ip = pdata.get("client_ip", "")
            m = re.search(r"10\.8\.0\.(\d+)", ip)
            if m:
                used_octets.add(int(m.group(1)))

        for i in range(2, 255):
            if i not in used_octets:
                return f"10.8.0.{i}"
        return "10.8.0.254"

    async def add_peer(self, form: WireGuardPeerForm) -> tuple[bool, str, WireGuardPeer | None]:
        """Creates a new client peer with Curve25519 keypair, optional PSK, updates wg0.conf and syncs."""
        clean_name = re.sub(r"[^a-zA-Z0-9_\-]", "", form.name.strip())
        if not clean_name:
            return False, "Invalid peer name. Use alphanumeric characters, dashes, or underscores.", None

        meta = self._read_metadata()
        if clean_name in meta.get("peers", {}):
            return False, f"Peer '{clean_name}' already exists.", None

        client_priv, client_pub = await self.driver.generate_wireguard_keypair()
        psk = ""
        if form.use_psk:
            psk = await self.driver.generate_wireguard_psk()

        client_ip = self._get_next_available_ip()
        allowed_ips = f"{client_ip}/32"
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        peer_data = {
            "name": clean_name,
            "public_key": client_pub,
            "private_key": client_priv,
            "preshared_key": psk,
            "client_ip": client_ip,
            "allowed_ips": allowed_ips,
            "tunnel_mode": form.tunnel_mode,
            "dns": form.dns.strip() or "1.1.1.1, 1.0.0.1",
            "enabled": True,
            "created_at": now_str,
        }

        # Save to metadata
        meta.setdefault("peers", {})[clean_name] = peer_data
        self._write_metadata(meta)

        # Append to wg0.conf
        conf_lines = [
            f"# Peer: {clean_name}",
            "[Peer]",
            f"PublicKey = {client_pub}",
        ]
        if psk:
            conf_lines.append(f"PresharedKey = {psk}")
        conf_lines.append(f"AllowedIPs = {allowed_ips}")
        conf_lines.append("")

        current_conf = self.driver.read_file(self.conf_path) if self.driver.file_exists(self.conf_path) else ""
        new_conf = current_conf.rstrip() + "\n\n" + "\n".join(conf_lines)
        self.driver.write_file(self.conf_path, new_conf)

        # Live sync if WireGuard is running
        raw_status = await self.driver.get_wireguard_status("wg0")
        if raw_status.get("active", False):
            await self.driver.sync_wireguard_peer(
                interface="wg0",
                public_key=client_pub,
                allowed_ips=allowed_ips,
                preshared_key=psk,
                remove=False,
            )

        peer_obj = WireGuardPeer(**peer_data)
        return True, f"Peer '{clean_name}' successfully created with IP {client_ip}", peer_obj

    async def delete_peer(self, peer_name: str) -> tuple[bool, str]:
        """Deletes peer from metadata, wg0.conf, and unregisters from live interface."""
        meta = self._read_metadata()
        if peer_name not in meta.get("peers", {}):
            return False, f"Peer '{peer_name}' not found"

        peer_data = meta["peers"].pop(peer_name)
        pub_key = peer_data.get("public_key", "")
        self._write_metadata(meta)

        # Remove peer block from wg0.conf
        if self.driver.file_exists(self.conf_path):
            conf_text = self.driver.read_file(self.conf_path)
            # Match # Peer: <name>\n[Peer]\n... until next section or EOF
            pattern = re.compile(
                rf"#\s*Peer:\s*{re.escape(peer_name)}\s*\n\[Peer\][\s\S]*?(?=(?:#\s*Peer:|\Z))",
                re.MULTILINE,
            )
            updated_conf = pattern.sub("", conf_text)
            self.driver.write_file(self.conf_path, updated_conf.strip() + "\n")

        # Unregister from live interface
        raw_status = await self.driver.get_wireguard_status("wg0")
        if raw_status.get("active", False) and pub_key:
            await self.driver.sync_wireguard_peer("wg0", pub_key, "", remove=True)

        return True, f"Peer '{peer_name}' deleted successfully"

    async def toggle_peer(self, peer_name: str) -> tuple[bool, str]:
        """Enables or disables peer access."""
        meta = self._read_metadata()
        if peer_name not in meta.get("peers", {}):
            return False, f"Peer '{peer_name}' not found"

        peer = meta["peers"][peer_name]
        is_enabled = not peer.get("enabled", True)
        peer["enabled"] = is_enabled
        self._write_metadata(meta)

        pub_key = peer.get("public_key", "")
        allowed_ips = peer.get("allowed_ips", "")
        psk = peer.get("preshared_key", "")

        raw_status = await self.driver.get_wireguard_status("wg0")
        if raw_status.get("active", False) and pub_key:
            if is_enabled:
                await self.driver.sync_wireguard_peer("wg0", pub_key, allowed_ips, preshared_key=psk, remove=False)
            else:
                await self.driver.sync_wireguard_peer("wg0", pub_key, "", remove=True)

        state_str = "enabled" if is_enabled else "disabled"
        return True, f"Peer '{peer_name}' {state_str}"

    async def generate_client_config(self, peer_name: str) -> str:
        """Generates ready-to-use WireGuard .conf file content for a client."""
        meta = self._read_metadata()
        peer = meta.get("peers", {}).get(peer_name)
        if not peer:
            return ""

        server_status = await self.get_status()
        server_pub = server_status.public_key or meta.get("server_public_key", "")
        if not server_pub and self.driver.file_exists(self.conf_path):
            conf_text = self.driver.read_file(self.conf_path)
            priv_m = re.search(r"^\s*PrivateKey\s*=\s*(.+)", conf_text, re.MULTILINE)
            if priv_m:
                # Fallback pubkey
                server_pub = meta.get("server_public_key", "")

        client_priv = peer.get("private_key", "")
        client_ip = peer.get("client_ip", "10.8.0.2")
        dns = peer.get("dns", "1.1.1.1, 1.0.0.1")
        psk = peer.get("preshared_key", "")
        tunnel_mode = peer.get("tunnel_mode", "full")

        server_endpoint = f"{server_status.server_ip}:{server_status.listen_port}"
        allowed_ips = "0.0.0.0/0, ::/0" if tunnel_mode == "full" else "10.8.0.0/24"

        lines = [
            f"# Pyx Panel WireGuard Client Configuration for: {peer_name}",
            "[Interface]",
            f"PrivateKey = {client_priv}",
            f"Address = {client_ip}/32",
            f"DNS = {dns}",
            "",
            "[Peer]",
            f"PublicKey = {server_pub}",
        ]
        if psk:
            lines.append(f"PresharedKey = {psk}")
        lines.append(f"Endpoint = {server_endpoint}")
        lines.append(f"AllowedIPs = {allowed_ips}")
        lines.append("PersistentKeepalive = 25")
        lines.append("")

        return "\n".join(lines)

    async def generate_client_qr_svg(self, peer_name: str) -> str:
        """Generates pixel-perfect SVG QR code for a peer configuration."""
        conf_text = await self.generate_client_config(peer_name)
        if not conf_text:
            return ""
        import qrcode
        import qrcode.image.svg

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=2,
            image_factory=qrcode.image.svg.SvgPathImage,
        )
        qr.add_data(conf_text)
        qr.make(fit=True)
        img = qr.make_image(attrib={"class": "wireguard-qr", "style": "max-width: 100%; height: auto;"})
        return img.to_string().decode("utf-8")

    async def update_settings(self, form: WireGuardSettingsForm) -> tuple[bool, str]:
        """Updates listen port, server IP, and default DNS in server configuration."""
        if not self.is_configured():
            return False, "WireGuard is not configured."

        conf_text = self.driver.read_file(self.conf_path)
        old_port_match = re.search(r"^\s*ListenPort\s*=\s*(\d+)", conf_text, re.MULTILINE)
        old_port = int(old_port_match.group(1)) if old_port_match else 51820
        new_port = form.server_port or old_port

        # Update port in wg0.conf
        if re.search(r"^\s*ListenPort\s*=", conf_text, re.MULTILINE):
            updated_conf = re.sub(r"^\s*ListenPort\s*=.*", f"ListenPort = {new_port}", conf_text, flags=re.MULTILINE)
        else:
            updated_conf = conf_text.replace("[Interface]", f"[Interface]\nListenPort = {new_port}")
        self.driver.write_file(self.conf_path, updated_conf)

        # Update metadata
        meta = self._read_metadata()
        if form.server_ip.strip():
            meta["server_ip"] = form.server_ip.strip()
        meta["server_port"] = new_port
        if form.dns.strip():
            meta["dns"] = form.dns.strip()
        self._write_metadata(meta)

        # If server was running, restart and adjust UFW rules
        raw_status = await self.driver.get_wireguard_status("wg0")
        if raw_status.get("active", False):
            # Close old port
            if old_port != new_port:
                await self.driver.ufw_delete_rule_by_spec(["allow", f"{old_port}/udp"])
            # Restart WireGuard
            await self.driver.stop_wireguard("wg0")
            await self.driver.start_wireguard("wg0")
            # Open new port
            await self.driver.ufw_allow(str(new_port), proto="udp", comment="WireGuard VPN")

        return True, f"Settings updated. Server port is now {new_port}/udp"


wireguard_manager = WireGuardManager()
