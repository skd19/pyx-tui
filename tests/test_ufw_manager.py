"""Unit tests for UFW firewall manager and security safeguards."""
import pytest
from pyx_panel.services.ufw_manager import AddRuleForm, UFWManager


@pytest.fixture
def ufw():
    return UFWManager()


@pytest.mark.asyncio
async def test_ufw_get_status(ufw):
    status = await ufw.get_status()
    assert status.active is True
    assert status.default_incoming == "deny"
    assert status.default_outgoing == "allow"
    assert len(status.rules) >= 3
    # Check that SSH 22 is present in initial mock state
    has_ssh = any(r.port == "22" for r in status.rules)
    assert has_ssh is True


def test_ufw_port_validation(ufw):
    # Valid ports
    ok, val = ufw.validate_port_spec("80")
    assert ok is True and val == "80"

    ok, val = ufw.validate_port_spec("8000:8010")
    assert ok is True and val == "8000:8010"

    ok, val = ufw.validate_port_spec("ssh")
    assert ok is True and val == "ssh"

    # Invalid ports
    ok, _ = ufw.validate_port_spec("")
    assert ok is False

    ok, _ = ufw.validate_port_spec("70000")
    assert ok is False

    ok, _ = ufw.validate_port_spec("8010:8000")  # start > end
    assert ok is False

    ok, _ = ufw.validate_port_spec("invalid port;")
    assert ok is False


@pytest.mark.asyncio
async def test_ufw_add_and_delete_rule(ufw):
    # Add a custom rule
    form = AddRuleForm(
        port="9090",
        proto="tcp",
        action="allow",
        comment="Test Custom Service",
    )
    success, msg = await ufw.add_rule(form)
    assert success is True
    assert "9090" in msg

    status = await ufw.get_status()
    added_rule = next((r for r in status.rules if r.port == "9090"), None)
    assert added_rule is not None
    assert added_rule.comment == "Test Custom Service"

    # Delete the rule
    del_ok, _ = await ufw.delete_rule(added_rule.index)
    assert del_ok is True

    # Verify rule is gone
    status_after = await ufw.get_status()
    assert not any(r.port == "9090" for r in status_after.rules)


@pytest.mark.asyncio
async def test_ufw_toggle_anti_lockout(ufw):
    # Temporarily remove SSH rule to test anti-lockout check
    status = await ufw.get_status()
    ssh_rule = next((r for r in status.rules if r.port == "22"), None)
    if ssh_rule:
        await ufw.delete_rule(ssh_rule.index)

    # Disable firewall first
    await ufw.toggle_ufw(enable=False)
    status_disabled = await ufw.get_status()
    assert status_disabled.active is False

    # Try to enable with auto_allow_ssh=False -> should block
    blocked, err_msg = await ufw.toggle_ufw(enable=True, auto_allow_ssh=False)
    assert blocked is False
    assert "Anti-Lockout Protection" in err_msg

    # Try to enable with auto_allow_ssh=True -> should allow and add SSH 22
    success, _ = await ufw.toggle_ufw(enable=True, auto_allow_ssh=True, panel_port=8000)
    assert success is True
    assert await ufw.is_ssh_allowed() is True


@pytest.mark.asyncio
async def test_ufw_apply_baseline_security(ufw):
    success, msg = await ufw.apply_baseline_security(panel_port=8000)
    assert success is True
    assert "Security baseline applied" in msg

    status = await ufw.get_status()
    assert status.active is True
    assert status.default_incoming == "deny"

    ports = [r.port for r in status.rules]
    assert "22" in ports
    assert "80" in ports
    assert "443" in ports
    assert "8000" in ports


@pytest.mark.asyncio
async def test_ufw_cloudflare_shield_lifecycle(ufw):
    # Ensure baseline first
    await ufw.apply_baseline_security(panel_port=8000)
    assert await ufw.is_cloudflare_shield_active() is False

    # Apply Cloudflare Shield with app port 8080 blocked
    success, msg = await ufw.apply_cloudflare_shield(panel_port=8000, block_app_port="8080")
    assert success is True
    assert "Cloudflare Web Shield active" in msg
    assert await ufw.is_cloudflare_shield_active() is True

    status = await ufw.get_status()
    # Check that app port 8080 is denied
    app_rule = next((r for r in status.rules if "8080" in r.port and r.action.startswith("DENY")), None)
    assert app_rule is not None

    # Check Cloudflare rules exist
    cf_rules = [r for r in status.rules if "cloudflare" in r.comment.lower() or "cloudflare" in r.from_src.lower()]
    assert len(cf_rules) > 10

    # Revert Cloudflare Shield
    rev_ok, rev_msg = await ufw.revert_cloudflare_shield(panel_port=8000)
    assert rev_ok is True
    assert "reverted" in rev_msg.lower()
    assert await ufw.is_cloudflare_shield_active() is False

    # Verify generic 80 and 443 are back
    status_reverted = await ufw.get_status()
    has_generic_80 = any(
        r.action.startswith("ALLOW") and ("80" in r.port) and ("Anywhere" in r.from_src)
        for r in status_reverted.rules
    )
    assert has_generic_80 is True


@pytest.mark.asyncio
async def test_ufw_open_and_close_panel_port(ufw):
    test_port = 9999
    # Ensure port is not present initially
    status_init = await ufw.get_status()
    assert not any(str(test_port) in r.port for r in status_init.rules)

    # 1. Open port on startup
    open_ok, open_msg = await ufw.open_panel_port(test_port)
    assert open_ok is True
    assert str(test_port) in open_msg

    status_open = await ufw.get_status()
    matching = [r for r in status_open.rules if str(test_port) in r.port]
    assert len(matching) >= 1
    assert any("pyx-panel" in r.comment.lower() or r.port == str(test_port) for r in matching)

    # 2. Calling open again should recognize already allowed
    open_again_ok, open_again_msg = await ufw.open_panel_port(test_port)
    assert open_again_ok is True
    assert "already allowed" in open_again_msg.lower()

    # 3. Close port on shutdown
    close_ok, close_msg = await ufw.close_panel_port(test_port)
    assert close_ok is True
    assert str(test_port) in close_msg

    status_closed = await ufw.get_status()
    assert not any(str(test_port) in r.port for r in status_closed.rules)


