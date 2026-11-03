#!/usr/bin/env bash
set -e

# ==============================================================================
# pyx-panel: VPS Setup & Installation Script
# ==============================================================================

echo "======================================================================"
echo "          Setting up pyx-panel on Linux VPS                           "
echo "======================================================================"

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run this installation script as root (sudo bash install.sh)"
    exit 1
fi

# 1. Install system prerequisites (Nginx, Certbot, UFW, Python3, curl)
echo "[+] Installing system prerequisites (Nginx, Certbot, UFW, curl)..."
apt-get update -y
apt-get install -y curl git nginx certbot python3-certbot-nginx ufw

# 2. Install uv if not present
if ! command -v uv &> /dev/null; then
    echo "[+] Installing uv fast Python package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

INSTALL_DIR="/opt/pyx-panel"

# 3. Setup application in /opt/pyx-panel
echo "[+] Setting up pyx-panel in $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Copy project files if running from local repository
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR"/
fi

cd "$INSTALL_DIR"

# 4. Sync dependencies with uv
echo "[+] Installing Python dependencies via uv..."
"$HOME/.local/bin/uv" sync

# 5. Create global command /usr/local/bin/pyx-panel
echo "[+] Creating global CLI command 'pyx-panel'..."
cat << 'EOF' > /usr/local/bin/pyx-panel
#!/usr/bin/env bash
export PATH="$HOME/.local/bin:/root/.local/bin:$PATH"
cd /opt/pyx-panel && exec uv run pyx-panel "$@"
EOF

chmod +x /usr/local/bin/pyx-panel

# Ensure Nginx sites-available and sites-enabled directories exist
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
mkdir -p /etc/systemd/system /opt/apps

# Remove default boilerplate site from sites-enabled to avoid conflicts
rm -f /etc/nginx/sites-enabled/default

echo "======================================================================"
echo "          pyx-panel Installation Complete!                            "
echo "======================================================================"
echo ""
echo "Whenever you want to manage your Nginx sites or Go services, simply run:"
echo ""
echo "    sudo pyx-panel"
echo ""
echo "It will print your one-click web dashboard link and auto-exit after"
echo "15 minutes of inactivity (or when you press Ctrl+C / click 'Shutdown')."
echo "======================================================================"
