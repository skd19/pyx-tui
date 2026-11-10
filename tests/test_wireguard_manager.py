"""Unit and integration tests for WireGuard VPN service, peer lifecycle, and zero-exposure port blocking."""
import pytest
from pyx_panel.config import settings
from pyx_panel.core.mock_driver import MockSystemDriver
from pyx_panel.services.security_manager import security_manager
from pyx_panel.services.wireguard_manager import (
    WireGuardPeerForm,
    WireGuardSettingsForm,
    WireGuardSetupForm,
    wireguard_manager,
)


@pytest.fixture(autouse=True)
def clean_wireguard_mock():
    """Resets mock wireguard files and driver state before each test."""
    driver = wireguard_manager.driver
    if isinstance(driver, MockSystemDriver):
        driver.wireguard_running = False
        driver.wireguard_listen_port = 51820
        driver.wireguard_public_key = ""
        driver.wireguard_private_key = ""
        driver.wireguard_peers.clear()
        # Clean wg0.conf and wg0-peers.json
        if driver.file_exists(wireguard_manager.conf_path):
            driver.delete_file(wireguard_manager.conf_path)
        if driver.file_exists(wireguard_manager.meta_path):
            driver.delete_file(wireguard_manager.meta_path)
        # Clean any leftover wireguard firewall rules
        driver.ufw_rules = [r for r in driver.ufw_rules if "wireguard" not in str(r.get("comment", "")).lower() and str(r.get("port", "")) not in ("51820", "51820/udp", "58291", "58291/udp")]

    yield

    if isinstance(driver, MockSystemDriver):
        driver.wireguard_running = False
        if driver.file_exists(wireguard_manager.conf_path):
            driver.delete_file(wireguard_manager.conf_path)
        if driver.file_exists(wireguard_manager.meta_path):
            driver.delete_file(wireguard_manager.meta_path)


@pytest.mark.asyncio
async def test_wireguard_auto_configure():
    # Verify unconfigured at start
    assert not wireguard_manager.is_configured()

    form = WireGuardSetupForm(
        server_port=51820,
        server_ip="203.0.113.10",
        subnet="10.8.0.1/24",
        dns="1.1.1.1, 1.0.0.1",
        network_interface="eth0",
    )
    ok, msg = await wireguard_manager.setup_server(form)
    assert ok, f"Setup failed: {msg}"
    assert wireguard_manager.is_configured()

    # Verify server status
    status = await wireguard_manager.get_status()
    assert status.configured
    assert status.running
    assert status.listen_port == 51820
    assert status.server_ip == "203.0.113.10"
    assert status.firewall_port_open

    # Verify IPv4 forwarding was set
    forwarding = await wireguard_manager.driver.read_sysctl_setting("net.ipv4.ip_forward")
    assert forwarding == "1"

    # Verify conf file contents
    conf_content = wireguard_manager.driver.read_file(wireguard_manager.conf_path)
    assert "[Interface]" in conf_content
    assert "Address = 10.8.0.1/24" in conf_content
    assert "ListenPort = 51820" in conf_content
    assert "PrivateKey =" in conf_content
    assert "iptables" in conf_content


@pytest.mark.asyncio
async def test_wireguard_start_and_stop_zero_exposure():
    # Setup server first
    form = WireGuardSetupForm(server_port=51820, server_ip="203.0.113.10")
    await wireguard_manager.setup_server(form)

    # Initially running -> port must be open
    assert await wireguard_manager.is_firewall_port_open(51820)

    # Stop server -> ZERO EXPOSURE must delete and block port
    stop_ok, stop_msg = await wireguard_manager.stop_server()
    assert stop_ok
    assert "Zero Exposure" in stop_msg

    status_stopped = await wireguard_manager.get_status()
    assert not status_stopped.running
    assert not status_stopped.firewall_port_open
    assert not await wireguard_manager.is_firewall_port_open(51820)

    # Start server again -> port restored
    start_ok, start_msg = await wireguard_manager.start_server()
    assert start_ok
    status_started = await wireguard_manager.get_status()
    assert status_started.running
    assert status_started.firewall_port_open
    assert await wireguard_manager.is_firewall_port_open(51820)


@pytest.mark.asyncio
async def test_wireguard_peer_lifecycle():
    # Setup server
    await wireguard_manager.setup_server(WireGuardSetupForm(server_port=51820, server_ip="203.0.113.10"))

    # 1. Add first peer (phone-1) with PSK
    peer1_form = WireGuardPeerForm(name="phone-1", use_psk=True, tunnel_mode="full", dns="1.1.1.1")
    ok1, msg1, peer1 = await wireguard_manager.add_peer(peer1_form)
    assert ok1
    assert peer1 is not None
    assert peer1.name == "phone-1"
    assert peer1.client_ip == "10.8.0.2"
    assert peer1.allowed_ips == "10.8.0.2/32"
    assert peer1.preshared_key != ""  # PSK generated
    assert peer1.enabled

    # 2. Add second peer (laptop-1)
    peer2_form = WireGuardPeerForm(name="laptop-1", use_psk=False, tunnel_mode="split")
    ok2, msg2, peer2 = await wireguard_manager.add_peer(peer2_form)
    assert ok2
    assert peer2 is not None
    assert peer2.client_ip == "10.8.0.3"
    assert peer2.preshared_key == ""

    # 3. List peers
    peers = await wireguard_manager.list_peers()
    assert len(peers) == 2
    peer_names = [p.name for p in peers]
    assert "phone-1" in peer_names
    assert "laptop-1" in peer_names

    # 4. Generate Client Config
    conf1 = await wireguard_manager.generate_client_config("phone-1")
    assert "[Interface]" in conf1
    assert "Address = 10.8.0.2/32" in conf1
    assert "PrivateKey =" in conf1
    assert "[Peer]" in conf1
    assert "Endpoint = 203.0.113.10:51820" in conf1
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf1
    assert "PersistentKeepalive = 25" in conf1
    assert "PresharedKey =" in conf1

    # Split tunnel check for laptop-1
    conf2 = await wireguard_manager.generate_client_config("laptop-1")
    assert "AllowedIPs = 10.8.0.0/24" in conf2
    assert "PersistentKeepalive = 25" in conf2

    # 5. Toggle peer
    toggle_ok, toggle_msg = await wireguard_manager.toggle_peer("phone-1")
    assert toggle_ok
    assert "disabled" in toggle_msg
    peers_toggled = await wireguard_manager.list_peers()
    p1 = next(p for p in peers_toggled if p.name == "phone-1")
    assert not p1.enabled

    # Toggle back
    toggle_ok2, _ = await wireguard_manager.toggle_peer("phone-1")
    assert toggle_ok2

    # 6. Delete peer
    del_ok, del_msg = await wireguard_manager.delete_peer("phone-1")
    assert del_ok
    peers_after_del = await wireguard_manager.list_peers()
    assert len(peers_after_del) == 1
    assert not any(p.name == "phone-1" for p in peers_after_del)


@pytest.mark.asyncio
async def test_wireguard_stealth_port_change():
    # Setup on 51820
    await wireguard_manager.setup_server(WireGuardSetupForm(server_port=51820, server_ip="203.0.113.10"))
    assert await wireguard_manager.is_firewall_port_open(51820)

    # Change to custom stealth port 58291
    upd_ok, upd_msg = await wireguard_manager.update_settings(
        WireGuardSettingsForm(server_port=58291, server_ip="203.0.113.10")
    )
    assert upd_ok
    assert "58291/udp" in upd_msg

    # Verify old port is closed and new port is open
    assert not await wireguard_manager.is_firewall_port_open(51820)
    assert await wireguard_manager.is_firewall_port_open(58291)

    status = await wireguard_manager.get_status()
    assert status.listen_port == 58291


@pytest.mark.asyncio
async def test_wireguard_security_audit_integration():
    # Setup server
    await wireguard_manager.setup_server(WireGuardSetupForm(server_port=51820, server_ip="203.0.113.10"))

    # When stopped and port blocked, audit should pass
    await wireguard_manager.stop_server()
    report = await security_manager.run_security_audit()
    wg_chk = next((c for c in report.checks if c.id == "wireguard_zero_exposure"), None)
    assert wg_chk is not None
    assert wg_chk.status == "PASS"

    # If port rule was accidentally left open while stopped
    await wireguard_manager.driver.ufw_allow("51820", proto="udp", comment="Accidental Rule")
    report_warn = await security_manager.run_security_audit()
    wg_chk_warn = next((c for c in report_warn.checks if c.id == "wireguard_zero_exposure"), None)
    assert wg_chk_warn is not None
    assert wg_chk_warn.status == "WARN"
    assert wg_chk_warn.remediation_action == "block_wireguard_port"

    # Trigger remediation
    rem_ok, rem_msg = await security_manager.block_wireguard_port()
    assert rem_ok
    assert not await wireguard_manager.is_firewall_port_open(51820)


@pytest.mark.asyncio
async def test_wireguard_web_endpoints(auth_client):
    # 1. GET /vpn
    resp = auth_client.get("/vpn")
    assert resp.status_code == 200
    assert "WireGuard VPN Service" in resp.text

    # 2. POST /vpn/setup
    resp_setup = auth_client.post(
        "/vpn/setup",
        data={
            "server_port": 51820,
            "server_ip": "203.0.113.20",
            "subnet": "10.8.0.1/24",
            "dns": "1.1.1.1, 1.0.0.1",
            "network_interface": "eth0",
        },
        follow_redirects=False,
    )
    assert resp_setup.status_code == 303
    assert "/vpn" in resp_setup.headers["location"]

    # 3. POST /vpn/peer/add
    resp_add = auth_client.post(
        "/vpn/peer/add",
        data={
            "name": "pixel-phone",
            "use_psk": "true",
            "tunnel_mode": "full",
            "dns": "1.1.1.1, 1.0.0.1",
        },
        follow_redirects=False,
    )
    assert resp_add.status_code == 303

    # 4. GET /vpn/peer/{name}/config (JSON for QR code)
    resp_cfg = auth_client.get("/vpn/peer/pixel-phone/config")
    assert resp_cfg.status_code == 200
    data = resp_cfg.json()
    assert data["name"] == "pixel-phone"
    assert "[Interface]" in data["config"]
    assert "203.0.113.20:51820" in data["config"]

    # 5. GET /vpn/peer/{name}/download (.conf file download)
    resp_dl = auth_client.get("/vpn/peer/pixel-phone/download")
    assert resp_dl.status_code == 200
    assert 'attachment; filename="pixel-phone.conf"' in resp_dl.headers["content-disposition"]
    assert "PersistentKeepalive = 25" in resp_dl.text

    # 6. POST /vpn/stop (port blocking)
    resp_stop = auth_client.post("/vpn/stop", follow_redirects=False)
    assert resp_stop.status_code == 303
    assert not await wireguard_manager.is_firewall_port_open(51820)

    # 7. POST /vpn/start (port opening)
    resp_start = auth_client.post("/vpn/start", follow_redirects=False)
    assert resp_start.status_code == 303
    assert await wireguard_manager.is_firewall_port_open(51820)

    # 8. POST /vpn/peer/{name}/delete
    resp_del = auth_client.post("/vpn/peer/pixel-phone/delete", follow_redirects=False)
    assert resp_del.status_code == 303
    peers = await wireguard_manager.list_peers()
    assert not any(p.name == "pixel-phone" for p in peers)
