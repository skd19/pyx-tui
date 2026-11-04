# pyx-panel: On-Demand VPS Nginx & Systemd Service Manager

A modern, lightweight Python web interface built with **FastAPI**, **HTMX**, and **Alpine.js**, packaged using **`uv`**, to manage Nginx virtual host configs, one-click SSL with Certbot, and systemd service lifecycles for backend applications (like Go servers) on Linux VPS hosts.

---

## ⚡ The Ephemeral, On-Demand Workflow

Unlike traditional heavy control panels that run permanently as exposed background daemons on public ports:

1. **You log into your VPS via SSH** whenever you need to configure or update your server.
2. **Run `sudo pyx-panel`** in your terminal.
3. The terminal prints a direct, one-click URL with an auto-login token:
   ```
   ========================================================================
      pyx-panel: On-Demand VPS Nginx & Service Manager (Production Host)
   ========================================================================
     Local URL:    http://localhost:8000/?token=qGvP38fUe5...
     Network URL:  http://198.51.100.24:8000/?token=qGvP38fUe5...
     Secret Token: qGvP38fUe5...
     Idle Timeout: Auto-shutdown after 15m of inactivity
     How to Exit:  Press Ctrl+C in terminal, or click 'Shutdown' in web UI
   ========================================================================
   ```
4. **Open the link in your browser** to manage your Nginx sites, Go services, and SSL.
5. **Exit cleanly**: Press `Ctrl+C` in your terminal or click the **"Shutdown Panel"** button in the top navigation bar.
6. **Fail-safe Auto-Shutdown**: If you close your browser or walk away, the built-in watchdog automatically terminates the server after 15 minutes of inactivity. Your Nginx sites and Go background apps continue running undisturbed on the VPS!

---

## 🚀 Features

- 🌐 **Nginx Site Management (CRUD)**:
  - Guided form wizard for **Reverse Proxy** (with WebSocket upgrade headers, client max body size, and proxy headers).
  - Guided form wizard for **Static Sites** (with SPA fallback support).
  - Raw configuration editor with syntax highlighting.
  - **Syntax Validation (`nginx -t`)**: Every config is verified before saving; syntax errors are reverted automatically so live sites never break.
  - Instant enable/disable symlink toggles.
- 🐹 **Go & Backend App Service Management (systemd)**:
  - Path-based systemd unit generator (`/etc/systemd/system/<app>.service`).
  - Full lifecycle controls: Start, Stop, Restart, Enable on boot, and Disable.
  - **Real-Time Live Logs**: Slide-over drawer streaming `journalctl -u <service> -f` over Server-Sent Events (SSE).
- 🔒 **One-Click SSL with Certbot**:
  - Automated DNS A-record pre-check against your VPS public IP using `httpx2` (prevents Let's Encrypt rate limits on unpointed domains).
  - Automatic `certbot --nginx` certificate issuance with auto-redirect to HTTPS.
  - Expiration tracking for installed certificates.
- 🛡️ **UFW Firewall & Port Security**:
  - View real-time firewall status, default incoming/outgoing policies, and numbered active port rules.
  - Allow or deny traffic on individual ports, port ranges, and protocols with custom comments.
  - **Anti-Lockout Protection**: Prevents enabling UFW unless SSH (22/tcp) and panel port access are preserved.
  - **Auto Ephemeral Panel Port**: Automatically allows the panel port (e.g. `8000/tcp`) in UFW on startup and deletes/closes the rule when the server stops (on Ctrl+C, UI shutdown, or watchdog timeout), leaving zero management ports exposed when stopped.
  - **1-Click Web Security Baseline**: Instantly sets default deny incoming, opens SSH (22), HTTP (80), HTTPS (443), and the panel port, and activates UFW.
- 📦 **System Packages & Prerequisites (`/packages`)**:
  - **Live Dependency Inspection**: Checks installation states and version numbers for `nginx`, `ufw`, `certbot`, `python3-certbot-nginx`, `curl`, `git`, `uv`, and `systemd`.
  - **1-Click Install All Missing**: Automatically executes non-interactive `apt-get` and `astral.sh` installers for missing tools.
  - **Real-Time Live Terminal Logs**: Slide-over drawer streaming `apt-get` output over Server-Sent Events (SSE).
- ☁️ **Cloudflare Web Shield & Direct IP Drop (Catch-All)**:
  - **Restrict Ports 80 & 443 to Cloudflare**: Locks incoming web traffic strictly to Cloudflare's official IPv4 and IPv6 CIDR blocks fetched live via `httpx2`, blocking direct external web visitors who attempt to bypass Cloudflare.
  - **App Port Hardening**: Denies public external access to backend app ports (e.g. `8080/tcp`) while apps communicate safely over localhost (`127.0.0.1`).
  - **Nginx Direct IP Reject**: Activates a default server block that drops scans targeting your raw server IP with HTTP `444` (connection closed with no response) and drops HTTPS with `ssl_reject_handshake on`.
  - **One-Click Revert**: Easily restore open public HTTP/HTTPS rules when needed.
- 💻 **Cross-Platform / Mock Development Driver**:
  - Automatically runs in Mock Mode on Windows/macOS or when passing `--mock`, simulating files, systemd, and logs in `.pyx_mock/` for local preview and development without root.

---

## 🛠️ Step-by-Step Guide: Hosting a Go Server on your VPS

### 1. Install pyx-panel on your VPS

Run the installation script as root on your Debian/Ubuntu VPS:

```bash
git clone https://github.com/your-username/pyx-panel.git /opt/pyx-panel
cd /opt/pyx-panel
sudo bash scripts/install.sh
```

The installer provisions `nginx`, `certbot`, and `uv`, sets up the Python environment, and links the global `pyx-panel` command.

### 2. Put your Go Binary on the VPS

Compile your Go server and place it on your VPS (e.g. at `/opt/apps/my-go-app/server`):

```bash
mkdir -p /opt/apps/my-go-app
# Copy your compiled binary here
chmod +x /opt/apps/my-go-app/server
```

### 3. Launch pyx-panel

```bash
sudo pyx-panel
```

Click the printed link in your terminal to open the web dashboard.

### 4. Create the Go Systemd Service

1. In the web UI, go to the **"Services"** tab.
2. Click **"Create New Service"**:
   - **Name**: `my-go-app`
   - **Executable Path**: `/opt/apps/my-go-app/server`
   - **Working Directory**: `/opt/apps/my-go-app`
   - **Environment Variables**: e.g. `PORT=8080`
3. Click **"Create Service"**. It generates the unit file, reloads systemd daemon, enables autostart on boot, and starts the service.
4. Click **"Logs"** to watch the real-time `journalctl -f` output and verify your Go app started listening on port `8080`.

### 5. Create the Nginx Reverse Proxy

1. Go to the **"sites"** tab and click **"Add New Site"**.
2. Fill out the **Reverse Proxy** wizard:
   - **Name**: `my-go-app`
   - **Domains**: `api.yourdomain.com`
   - **Upstream**: `http://127.0.0.1:8080`
   - Check **"Enable WebSocket Upgrades"** if your app uses WebSockets.
3. Click **"Create Reverse Proxy"**. pyx-panel writes `/etc/nginx/sites-available/my-go-app.conf`, validates it with `nginx -t`, creates the symlink in `sites-enabled/`, and reloads Nginx.

### 6. Add One-Click SSL (HTTPS)

1. Go to the **"ssl"** tab.
2. Select your domain (`api.yourdomain.com`).
3. Click **"Pre-check DNS Resolution"** to verify that your domain's A-record points to your VPS IP.
4. Click **"Run Certbot & Enable SSL"**. Certbot issues your certificate and automatically updates Nginx with HTTPS and HTTP-to-HTTPS redirect.

### 7. Harden Server with UFW Firewall & Cloudflare Shield

1. Go to the **"firewall"** tab.
2. Click **"Apply Security Baseline"** to automatically:
   - Ensure **SSH (22/tcp)**, **HTTP (80/tcp)**, **HTTPS (443/tcp)**, and the panel port are explicitly allowed.
   - Set default policies: **deny incoming**, **allow outgoing**.
   - Enable UFW with anti-lockout protection.
3. If using Cloudflare Proxied mode (orange-cloud DNS):
   - Click **"Cloudflare Shield"** to restrict ports 80 and 443 exclusively to Cloudflare's IP ranges and block direct public access to your backend application port (e.g. `8080`).
   - Click **"Direct IP Reject"** toggle to activate Nginx catch-all dropping raw IP scans with HTTP 444 and SSL handshake rejection.
4. Add custom rules for any auxiliary services using the **"Add Port Rule"** modal.

### 8. Stop the Panel

When done managing:
- Click **"Shutdown Panel"** in the top navigation bar, or press `Ctrl+C` in your terminal.
- Your Go application and Nginx sites continue running 24/7 on systemd!

---

## ⚙️ CLI Options & Flags

```bash
sudo pyx-panel [OPTIONS]

Options:
  --port PORT        Port to bind web panel (default: 8000)
  --host HOST        Host address to bind (default: 0.0.0.0)
  --timeout MINUTES  Inactivity timeout in minutes before auto-shutdown (default: 15, 0 to disable)
  --token TOKEN      Custom secret access token (auto-generated if omitted)
  --mock             Force mock system mode (no root or Linux systemd required)
```

---

## 🧪 Testing

Run the full automated test suite using `uv`:

```bash
uv run pytest -v
```
