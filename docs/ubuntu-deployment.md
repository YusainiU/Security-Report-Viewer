# Ubuntu deployment guide — private access over SSH

This guide installs Security Report Viewer on a remote Ubuntu server as an unprivileged systemd service, accessed from your own computer through an encrypted SSH tunnel. No Apache configuration, public HTTP port, database or PHP runtime is required.

## Choose your deployment approach

| Approach | When to use |
| --- | --- |
| Run the standalone scanner remotely and upload its report locally | Occasional scans or when elevated log access is required |
| Remote Rust service with SSH forwarding (recommended) | Regular private access to server reports |
| Apache HTTPS reverse proxy | Only after implementing appropriate authentication and security controls |

The current application has no built-in authentication. Do not expose the application listening port publicly. Loopback binding does not protect against other local users or all browser-origin attacks; use a trusted single-administrator host and browser environment. SSH access must be restricted to trusted users.

## 1. Install prerequisites

Connect to your Ubuntu server using your normal administrative SSH account.

```bash
sudo apt update
sudo apt install -y build-essential curl git python3 gzip
```

Install Rust if needed, following https://rustup.rs/ under your normal account (not root):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

## 2. Clone and build

```bash
mkdir -p ~/applications
cd ~/applications
git clone https://github.com/YusainiU/Security-Report-Viewer.git
cd Security-Report-Viewer
cargo test && cargo build --release
```

For a private repository, configure GitHub authentication first. Do not proceed if tests or compilation fail.

## 3. Create the service account and install

Run the following once. If the account already exists, skip useradd.

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin securityviewer
sudo usermod -aG adm securityviewer
sudo install -d -m 755 /opt/security-report-viewer
sudo install -d -m 700 -o securityviewer -g securityviewer /opt/security-report-viewer/reports
sudo install -m 755 -o root -g root target/release/security-report-viewer /opt/security-report-viewer/security-report-viewer
```

The adm group provides access to sensitive logs. Grant it only if necessary. Some protected logs may still be unreadable; inspect scan coverage and permission diagnostics. Never run the web application as root or make system logs world-readable. For logs requiring elevated permissions, use the reviewed standalone scanner manually and upload the resulting report securely.

## 4. Configure systemd

Create /etc/systemd/system/security-report-viewer.service using sudo nano and insert:

```ini
[Unit]
Description=Security Report Viewer
After=network.target

[Service]
Type=simple
User=securityviewer
Group=securityviewer
WorkingDirectory=/opt/security-report-viewer
ExecStart=/opt/security-report-viewer/security-report-viewer
Environment=APP_PORT=8080
Environment=LOG_ROOT=/var/log
Environment=THRESHOLD=20
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/security-report-viewer/reports

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now security-report-viewer
sudo systemctl status security-report-viewer
sudo ss -ltnp | grep ':8080'
```

Verify the listener is 127.0.0.1:8080, not 0.0.0.0 or a public address. If startup fails, inspect:

```bash
sudo journalctl -u security-report-viewer -n 100 --no-pager
```

## 5. Connect from your computer

From your local WSL, Linux, macOS or Windows OpenSSH terminal (not the remote server):

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8080:127.0.0.1:8080 your-username@your-server-ip
```

Replace the username and address. Keep the terminal open and visit http://localhost:8080 in your browser. The browser connects through SSH to the remote application, which scans the remote server's logs.

If local port 8080 is occupied:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9090:127.0.0.1:8080 your-username@your-server-ip
```

Visit http://localhost:9090 instead. Close the tunnel with Ctrl+C. The remote service continues running.

Do not open port 8080 in UFW or the cloud firewall. Existing Apache sites and HTTPS configuration can remain unchanged.

## 6. Use the application

Run a security scan when the service account has appropriate log access. Open or delete saved reports, or download the standalone scanner to run manually on the target server and upload its TXT or JSON output. Review scan coverage and warnings before interpreting results. Zero detections do not establish that the server is secure.

Reports are stored in /opt/security-report-viewer/reports/. Keep this directory private, restrict backups, and remove reports when no longer needed.

## 7. Update the application

```bash
cd ~/applications/Security-Report-Viewer
git switch main
git pull --ff-only origin main
cargo test && cargo build --release
```

Only if the build succeeds, install the new binary:

```bash
sudo systemctl stop security-report-viewer
sudo cp -p /opt/security-report-viewer/security-report-viewer /opt/security-report-viewer/security-report-viewer.previous
sudo install -m 755 -o root -g root target/release/security-report-viewer /opt/security-report-viewer/security-report-viewer
sudo systemctl start security-report-viewer
sudo systemctl status security-report-viewer
```

Existing reports are retained. If the new service fails, restore the previous binary while the service is stopped, then restart it.

## 8. Troubleshooting and maintenance

- Connection refused: check systemd status, the loopback listener and the SSH tunnel.
- SSH forwarding denied: ask the SSH administrator to check forwarding policy; do not weaken SSH security indiscriminately.
- Incomplete scans: check the service account's group membership and log permissions; use the standalone scanner if needed.
- Port conflict: distinguish local and remote listeners; see section 8.1.
- Stop or disable the service with sudo systemctl disable --now security-report-viewer.
- Follow service logs with sudo journalctl -u security-report-viewer -f.


### 8.1 Remote port 8080 already in use

Observed during deployment:

```text
Cannot bind port 8080: Os { code: 98, kind: AddrInUse, message: "Address already in use" }
Main process exited, code=exited, status=101/n/a
```

Older binaries panic with exit status 101; updated binaries report a friendly startup error and exit with status 1. With Restart=on-failure, systemd may repeatedly restart the service.

Stop the restart cycle and identify the existing listener:

```bash
sudo systemctl stop security-report-viewer
sudo ss -ltnp 'sport = :8080'
sudo ss -ltnp 'sport = :9080'
```

Do not terminate an unknown process. If 9080 is free, install the updated binary supporting APP_PORT (see section 7; keep the service stopped until configuration is corrected). Then run:

```bash
sudo systemctl edit security-report-viewer
```

Insert only the following in the editable area above the discard marker, without Markdown fences:

```ini
[Service]
Environment=APP_PORT=9080
```

This creates /etc/systemd/system/security-report-viewer.service.d/override.conf. Alternatively, add Environment=APP_PORT=9080 to the existing [Service] section in the original unit file; use one approach, not both.

Validate and restart using the commands in section 8.2 below. From your local computer, forward the new remote port:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9080:127.0.0.1:9080 your-username@your-server-ip
```

Visit http://localhost:9080. Changing only the local forwarded port does not resolve a remote listening-port conflict.

### 8.2 Bad unit file setting — duplicate ExecStart

Observed during deployment after editing the service configuration:

```text
Failed to restart security-report-viewer.service: Unit security-report-viewer.service has a bad unit file setting.
```

The verification command identified the cause:

```text
Service has more than one ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.
```

The service uses Type=simple, so only one effective ExecStart command is allowed. Copying the entire original unit into a drop-in override can cause this problem. Systemd merges the original unit and its drop-ins.

Inspect both files:

```bash
sudo systemctl cat security-report-viewer
sudo systemd-analyze verify security-report-viewer.service
```

The original file, /etc/systemd/system/security-report-viewer.service, should retain the full configuration from section 4, including exactly one ExecStart=/opt/security-report-viewer/security-report-viewer.

If the port override was created solely for APP_PORT, edit it:

```bash
sudo nano /etc/systemd/system/security-report-viewer.service.d/override.conf
```

Replace its contents with only:

```ini
[Service]
Environment=APP_PORT=9080
```

If the drop-in contains other intentional customizations, preserve them and remove only the unintended duplicate ExecStart or duplicated unit settings. If the duplicate is in the original unit or another drop-in, correct that file instead. Do not change Type to oneshot to bypass the error.

Reload and validate:

```bash
sudo systemctl daemon-reload
sudo systemd-analyze verify security-report-viewer.service
```

Once the service-specific errors are resolved:

```bash
sudo systemctl reset-failed security-report-viewer
sudo systemctl restart security-report-viewer
sudo systemctl status security-report-viewer
sudo systemctl show security-report-viewer -p Environment
sudo ss -ltnp 'sport = :9080'
curl -I http://127.0.0.1:9080
```

Expected: active (running), APP_PORT=9080, a listener on 127.0.0.1:9080 and a successful HTTP response. Substitute your chosen port if different. No Rust rebuild is needed to fix duplicate unit settings, provided the installed binary already supports APP_PORT.

### 8.3 Unrelated CPUAccounting warning

The same verification also reported:

```text
/usr/lib/systemd/system/system-xfs_scrub.slice:15: Support for option CPUAccounting= has been removed and it is ignored
```

This warning concerns an unrelated Ubuntu system unit, not Security Report Viewer. It can be ignored for this deployment; do not edit the distribution-managed unit merely to fix this application. Resolve the duplicate ExecStart error first.


## 9. Public HTTPS deployment is not recommended yet

Before exposing the application via Apache or another reverse proxy, implement authentication, session and CSRF protection, host validation, rate limiting, audit logging, report retention, sensitive-log redaction and configurable base paths. HTTPS alone is not sufficient.

## Verification

This is a manual deployment guide, not an automated installer. The configuration should be validated on the target Ubuntu host before relying on it. No deployment is performed by this document.


## Configurable listening port

The application listens only on IPv4 loopback (127.0.0.1). Set `APP_PORT` to a free TCP port (1–65535); the default is 8080. `LOG_ROOT` defaults to /var/log and `THRESHOLD` defaults to 20.

For local development: `APP_PORT=9080 cargo run --release`.

For systemd, run `sudo systemctl edit security-report-viewer` and add:

```ini
[Service]
Environment=APP_PORT=9080
```

After installing the updated executable, run `sudo systemctl daemon-reload` and `sudo systemctl restart security-report-viewer`. Verify with `sudo ss -ltnp 'sport = :9080'`. From your local computer use `ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9080:127.0.0.1:9080 your-username@your-server-ip` and visit http://localhost:9080. No public firewall rule is needed. If the port is occupied, choose another free port; startup reports the error and exits without a panic.
