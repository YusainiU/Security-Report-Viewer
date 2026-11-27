# Security Report Viewer

A lightweight local security reporting dashboard built with **Rust**, **Axum** and a bundled **Bash** log scanner. Analyse server logs without sending them to an external service.

## Features

- **Run Security Scan** invokes the bundled `security-log-scan-v3.sh` on the host and shows its parsed results.
- **Upload Report** parses existing v2 and v3 text or v3 JSON reports (up to 10 MiB) without saving the upload.
- **Saved Reports** keeps generated reports in `reports/`, allowing them to be opened after a restart.
- Severity overview, correlated IP analysis, request counters, searchable/filterable results, and sample evidence.
- Print the dashboard or save it to PDF using your browser.
- No JavaScript toolchain, database, or third-party log service required.

## Scanner v3.0 reliability

Python 3 is required by the standalone Bash scanner. The original v2 script remains available in the repository. The integrated scanner saves text; manual scans default to both text and JSON.

```bash
bash security-log-scan-v3.sh --help
bash security-log-scan-v3.sh --days 7 --format both
bash security-log-scan-v3.sh --from 2026-11-20 --to 2026-11-27 --output .
```

The default scans all matching retained files, bounded by 64 MiB of decompressed input and a best-effort 120-second collection deadline. The integrated viewer also retains its external five-minute timeout. Date filtering supports Apache timestamps and ISO timestamps; yearless syslog and other unrecognised dates are excluded and counted, not guessed. The v3 collector does not currently read journald; journal-only hosts will show missing authentication coverage. Missing, unreadable or truncated sources produce partial coverage. JSON includes metadata, structured IP counters and the compatible report text; the viewer currently renders the report text and coverage warning. No logs are changed.

## Requirements

- Linux (Ubuntu / WSL Ubuntu supported)
- Rust stable and Cargo (install with [rustup](https://rustup.rs/))
- Bash, `awk`, `grep`, `find`, `sort`, `gzip`, `timeout`, `journalctl` (optional fallback for authentication logs)
- Permission to read the log files being scanned

## Run locally

```bash
cargo check
cargo test
cargo run --release
```

Open **http://127.0.0.1:8080**. The application binds to loopback only. Try `sample-report.txt` before scanning live logs.

## Manual scanning and report upload

Use **Download security scanner** in the dashboard to obtain the exact bundled Bash script. Transfer it securely to the Linux host to be scanned, review it, and open a terminal there. From the directory containing the script:

```bash
chmod 700 security-log-scan-v3.sh
script="$(realpath security-log-scan-v3.sh)"
mkdir -p ~/security-reports
chmod 700 ~/security-reports
cd ~/security-reports
bash "$script"
```

If authorised and necessary for protected logs, run `sudo /bin/bash "$script"` instead. The generated file will be root-owned; use the exact filename printed after **Report saved:** to change ownership of that file only:

```bash
sudo chown "$(id -u):$(id -g)" -- ./security-report-EXACT-NAME.txt
chmod 600 ./security-report-EXACT-NAME.txt
```

Replace the example filename with the actual filename. Securely transfer the report to your browser's machine if needed, select it under **Upload a security report**, and click **Analyse report**. Do not run the Rust server as root. Treat report contents as sensitive; permission errors may indicate incomplete coverage.

## Scan configuration

```bash
LOG_ROOT=/var/log THRESHOLD=20 cargo run --release
```

`LOG_ROOT` selects a local directory to scan. `THRESHOLD` sets the repeated-event threshold passed to the scanner (default: 20). Only the bundled script is executable through the application. The scanner runs as the same **unprivileged** OS account as the Rust server, has a five-minute timeout, and permits only one concurrent scan.

The log files may not all be readable to your account. On Ubuntu, membership in the trusted `adm` group grants access to many logs (re-login required):

```bash
sudo usermod -aG adm "$USER"
```

This expands access to sensitive logs. Do not run the web server as root or expose it publicly to make scanning easier. Missing log permissions can cause incomplete results.

## Saved report storage

Automatically generated files are written into `reports/` beneath the process's working directory. The directory is created with mode `0700`, and reports with `0600` permissions. It is ignored by Git. Uploaded reports are parsed in memory only. Report text can include IP addresses and sensitive request paths; protect backups and delete reports according to your retention policy.

## Connecting to a remote Ubuntu server

Run the Rust app on the server, then from your computer:

```bash
ssh -L 8080:127.0.0.1:8080 user@server
```

Open http://127.0.0.1:8080 locally. The scanner reads the **server's own** `/var/log`, not the browser's computer logs.

**Security:** The viewer has no authentication. Never expose port 8080 to the public internet or reverse proxy it publicly. Keep the loopback bind, and access remotely over SSH. Scan results are heuristic; suspicious HTTP 2xx/5xx responses and SSH activity do not prove a compromise. No firewall rules are altered, and the scanner does not delete logs.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
bash -n security-log-scan-v3.sh
```

## License

No license has been granted in this repository yet. Add a `LICENSE` file before distributing or accepting outside contributions.