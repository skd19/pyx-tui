"""Comprehensive integration tests for all web routes, site actions, and service lifecycles."""
import pytest
from pyx_panel.config import settings
from pyx_panel.web.auth import COOKIE_NAME


def test_unauthenticated_redirect(client):
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 307
    assert res.headers["location"] == "/login"


def test_token_query_auto_login(client):
    token = settings.get_token()
    res = client.get(f"/?token={token}", follow_redirects=False)
    assert res.status_code == 303
    assert COOKIE_NAME in res.cookies


def test_login_page_renders(client):
    res = client.get("/login")
    assert res.status_code == 200
    assert "Secret Access Token" in res.text


def test_authenticated_dashboard(auth_client):
    res = auth_client.get("/")
    assert res.status_code == 200
    assert "pyx-panel" in res.text
    assert "Dashboard" in res.text


def test_sites_flow(auth_client):
    # 1. View sites page
    res = auth_client.get("/sites")
    assert res.status_code == 200

    # 2. Create reverse proxy with www_handling
    res_create = auth_client.post(
        "/sites/new/reverse-proxy",
        data={
            "name": "e2e-go-app",
            "domains": "example.com",
            "upstream": "127.0.0.1:8080",
            "www_handling": "redirect_to_www",
            "enable_websocket": "true",
            "client_max_body_size": "64M",
            "enable_immediately": "true",
        },
        follow_redirects=True,
    )
    assert res_create.status_code == 200
    assert "e2e-go-app" in res_create.text

    # 3. View site editor (should have redirect block to www)
    res_editor = auth_client.get("/sites/e2e-go-app")
    assert res_editor.status_code == 200
    assert "return 301 $scheme://www.example.com$request_uri;" in res_editor.text
    assert "server_name www.example.com;" in res_editor.text

    # 3b. Test snippet API endpoint
    res_snip = auth_client.get("/sites/snippets/cloudflare-keepalive")
    assert res_snip.status_code == 200
    snip_data = res_snip.json()
    assert "keepalive_timeout 120s;" in snip_data["content"]

    res_snip_full = auth_client.get("/sites/snippets/full-go-template?domain=example.com&upstream=127.0.0.1:8080")
    assert res_snip_full.status_code == 200
    assert "listen 443 ssl http2;" in res_snip_full.json()["content"]

    # 4. Toggle site
    res_toggle = auth_client.post("/sites/e2e-go-app/toggle", follow_redirects=True)
    assert res_toggle.status_code == 200

    # 5. Revert site SSL
    res_rem_ssl = auth_client.post("/sites/e2e-go-app/remove-ssl", follow_redirects=True)
    assert res_rem_ssl.status_code == 200

    # 6. Delete site
    res_del = auth_client.post("/sites/e2e-go-app/delete", follow_redirects=True)
    assert res_del.status_code == 200


def test_services_flow(auth_client):
    # 1. View services page
    res = auth_client.get("/services")
    assert res.status_code == 200

    # 2. Create new service
    res_create = auth_client.post(
        "/services/new",
        data={
            "name": "e2e-service",
            "description": "E2E Service",
            "exec_start": "/usr/bin/python3 -m http.server 9999",
            "working_dir": "/tmp",
            "user": "root",
            "environment": "PORT=9999",
            "restart": "always",
            "restart_sec": "3s",
            "autostart": "true",
        },
        follow_redirects=True,
    )
    assert res_create.status_code == 200
    assert "e2e-service" in res_create.text

    # 3. Service lifecycle: restart & stop
    res_restart = auth_client.post("/services/e2e-service/restart", follow_redirects=True)
    assert res_restart.status_code == 200

    res_stop = auth_client.post("/services/e2e-service/stop", follow_redirects=True)
    assert res_stop.status_code == 200

    # 4. Delete service
    res_del = auth_client.post("/services/e2e-service/delete", follow_redirects=True)
    assert res_del.status_code == 200


def test_ssl_flow(auth_client):
    # 1. View SSL page
    res = auth_client.get("/ssl")
    assert res.status_code == 200
    assert "SSL Certificates" in res.text

    # 2. Check DNS API with include_www
    res_dns = auth_client.post("/ssl/check-dns", data={"domain": "localhost", "include_www": "true"})
    assert res_dns.status_code == 200
    data = res_dns.json()
    assert data["domain"] == "localhost"
    assert "vps_ip" in data
    assert "details" in data

    # 3. Provision SSL with include_www
    res_prov = auth_client.post(
        "/ssl/provision",
        data={"domain": "localhost", "email": "admin@example.com", "force": "true", "include_www": "true"},
        follow_redirects=True,
    )
    assert res_prov.status_code == 200

    # 4. Remove SSL
    res_rem = auth_client.post(
        "/ssl/remove",
        data={"cert_name": "localhost"},
        follow_redirects=True,
    )
    assert res_rem.status_code == 200
    assert "removed successfully" in res_rem.text


def test_firewall_flow(auth_client):
    # 1. View firewall page
    res = auth_client.get("/firewall")
    assert res.status_code == 200
    assert "Firewall & Port Security" in res.text

    # 2. Add rule
    res_add = auth_client.post(
        "/firewall/rule/add",
        data={
            "port": "5432",
            "proto": "tcp",
            "action": "allow",
            "comment": "Postgres",
        },
        follow_redirects=True,
    )
    assert res_add.status_code == 200
    assert "5432" in res_add.text

    # 3. Apply baseline preset
    res_preset = auth_client.post("/firewall/preset/web-baseline", follow_redirects=True)
    assert res_preset.status_code == 200
    assert "Security baseline applied" in res_preset.text

    # 4. Apply Cloudflare Web Shield preset
    res_cf = auth_client.post(
        "/firewall/preset/cloudflare-shield",
        data={"block_app_port": "8080"},
        follow_redirects=True,
    )
    assert res_cf.status_code == 200
    assert "Cloudflare Web Shield" in res_cf.text

    # 5. Toggle Nginx Direct IP Drop (Catch-All)
    res_dd_on = auth_client.post(
        "/firewall/default-deny/toggle",
        follow_redirects=True,
    )
    assert res_dd_on.status_code == 200
    assert "Direct IP reject enabled" in res_dd_on.text

    res_dd_off = auth_client.post(
        "/firewall/default-deny/toggle",
        follow_redirects=True,
    )
    assert res_dd_off.status_code == 200
    assert "Direct IP reject disabled" in res_dd_off.text

    # 6. Revert Cloudflare Shield
    res_cf_rev = auth_client.post(
        "/firewall/preset/cloudflare-revert",
        follow_redirects=True,
    )
    assert res_cf_rev.status_code == 200
    assert "Reverted Cloudflare Web Shield" in res_cf_rev.text


def test_system_apis(auth_client):
    # Test Nginx
    res_test = auth_client.post("/api/system/test-nginx")
    assert res_test.status_code == 200
    assert res_test.json()["valid"] is True

    # Reload Nginx
    res_reload = auth_client.post("/api/system/reload-nginx")
    assert res_reload.status_code == 200
    assert res_reload.json()["success"] is True

    # Watchdog
    res_wd = auth_client.get("/api/system/watchdog")
    assert res_wd.status_code == 200
    assert res_wd.json()["remaining_seconds"] > 0


def test_packages_flow(auth_client):
    # 1. View packages overview page
    res = auth_client.get("/packages")
    assert res.status_code == 200
    assert "System Packages & Prerequisites" in res.text
    assert "Nginx Web Server" in res.text
    assert "UFW Firewall" in res.text
    assert "Certbot" in res.text
    assert "python3-certbot-nginx" in res.text

    # 2. Trigger install single package
    res_single = auth_client.post("/packages/git/install", follow_redirects=True)
    assert res_single.status_code == 200
    assert "Package git installed" in res_single.text

    # 3. Trigger install-all
    res_all = auth_client.post("/packages/install-all", follow_redirects=True)
    assert res_all.status_code == 200

    # 4. Test SSE installation log stream
    res_stream = auth_client.get("/packages/install/stream?pkgs=curl")
    assert res_stream.status_code == 200
    assert "text/event-stream" in res_stream.headers["content-type"]
    assert "data:" in res_stream.text


def test_security_center_flow(auth_client):
    # 1. View security overview page
    res = auth_client.get("/security")
    assert res.status_code == 200
    assert "VPS Security Center" in res.text
    assert "Security Audit Findings" in res.text
    assert "Listening Sockets & Exposure Scanner" in res.text
    assert "SSH Brute-Force Defense" in res.text

    # 2. Re-run audit
    res_audit = auth_client.post("/security/audit/run", follow_redirects=True)
    assert res_audit.status_code == 200
    assert "Security audit refreshed" in res_audit.text

    # 3. Toggle Nginx Security Guard
    res_guard = auth_client.post("/security/nginx-guard/toggle", follow_redirects=True)
    assert res_guard.status_code == 200
    assert "Nginx Global Security Guard" in res_guard.text

    # 4. Toggle Direct IP Drop
    res_drop = auth_client.post("/security/direct-ip-drop/toggle", follow_redirects=True)
    assert res_drop.status_code == 200

    # 5. Kernel Sysctl Hardening
    res_kernel = auth_client.post("/security/kernel/harden", follow_redirects=True)
    assert res_kernel.status_code == 200
    assert "parameters applied" in res_kernel.text.lower()

    # 6. Isolate Port with UFW
    res_iso = auth_client.post(
        "/security/ports/isolate",
        data={"port": "8080", "proto": "tcp"},
        follow_redirects=True,
    )
    assert res_iso.status_code == 200
    assert "isolated" in res_iso.text

    # 7. SSH Hardening (keys only & root)
    res_ssh = auth_client.post(
        "/security/ssh/harden",
        data={"mode": "full"},
        follow_redirects=True,
    )
    assert res_ssh.status_code == 200

    # 8. 1-Click Harden All
    res_all = auth_client.post("/security/harden-all", follow_redirects=True)
    assert res_all.status_code == 200
    assert "All security hardening modules applied successfully" in res_all.text


