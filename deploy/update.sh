#!/usr/bin/env bash
# Update an existing installation; run as the normal deployment account.
set -Eeuo pipefail
service=security-report-viewer.service
binary=/opt/security-report-viewer/security-report-viewer
backup="$binary.previous"
port=${1:-8080}
if (( EUID == 0 )); then echo "Run as your normal deployment user, not root." >&2; exit 1; fi
if (( $# > 1 )) || [[ ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )); then
    echo "Usage: bash deploy/update.sh [remote-port]" >&2; exit 1
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
for cmd in git cargo sudo systemctl ss curl sha256sum flock cmp install; do
    command -v "$cmd" >/dev/null || { echo "Missing requirement: $cmd" >&2; exit 1; }
done
die() { echo "$*" >&2; exit 1; }
[[ $(git branch --show-current) == main ]] || die "Switch to main first."
[[ -z $(git status --porcelain --untracked-files=no) ]] || die "Commit or stash tracked changes first."
# Cargo.lock may be generated locally; other untracked files are not removed.
sudo -v
# Lock in the existing root-owned installation directory, across clones.
sudo touch /opt/security-report-viewer/.update.lock
# The lock is opened read-only by the deployment account.
exec 9</opt/security-report-viewer/.update.lock
flock -n 9 || die "Another update is running."
[[ -f $binary && ! -L $binary ]] || die "Existing regular installed binary required."
systemctl is-active --quiet "$service" || die "Service must be running before updating."
[[ $(systemctl show "$service" -p ExecStart --value) == *"path=$binary ;"* ]] || die "Unexpected ExecStart; inspect service configuration."
pid=$(systemctl show "$service" -p MainPID --value)
[[ $pid =~ ^[1-9][0-9]*$ ]] || die "No service PID."
listener=$(sudo ss -H -ltnp "sport = :$port")
[[ $listener == *"127.0.0.1:$port "* && $listener == *"pid=$pid,"* && $listener != *$'\n'* ]] || die "Port must match the service's sole loopback listener; pass the configured remote port."
git pull --ff-only origin main
cargo test
cargo build --release
built=target/release/security-report-viewer
[[ -f $built ]] || die "Release executable not found."
# Save the known installed binary before any downtime.
sudo cp -p -- "$binary" "$backup"
phase=stopping
health() {
    local p listeners
    for ((i=0;i<20;i++)); do
        p=$(systemctl show "$service" -p MainPID --value)
        if [[ $p =~ ^[1-9][0-9]*$ ]] && systemctl is-active --quiet "$service" &&
           sudo cmp -s "/proc/$p/exe" "$binary"; then
            listeners=$(sudo ss -H -ltnp "sport = :$port") || return 1
            if [[ $listeners == *"127.0.0.1:$port "* && $listeners == *"pid=$p,"* && $listeners != *$'\n'* ]] &&
               curl --noproxy '*' -fsS --max-time 3 "http://127.0.0.1:$port/" >/dev/null; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}
recover() {
    local rc=$?
    trap - EXIT INT TERM
    (( rc != 0 )) || return 0
    set +e
    echo "Update failed during $phase. Inspecting recovery options." >&2
    if [[ $phase == installing || $phase == starting ]]; then
        if sudo systemctl stop "$service" && [[ -z $(sudo ss -H -ltn "sport = :$port")" && $? == 0 ]]; then
            if sudo install -m 755 -o root -g root -- "$backup" "$binary" &&
               sudo systemctl start "$service" && health; then
                echo "Previous installed version restored." >&2
            else
                echo "Rollback failed; inspect service journal and $backup." >&2
            fi
        else
            echo "Cannot safely roll back: service stop or port check failed." >&2
        fi
    else
        echo "Binary unchanged; inspect service state and port before restarting." >&2
    fi
    exit "$rc"
}
trap recover EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sudo systemctl stop "$service"
remaining=$(sudo ss -H -ltn "sport = :$port")
[[ -z $remaining ]] || die "Port still occupied; refusing to replace executable."
phase=installing
sudo install -m 755 -o root -g root -- "$built" "$binary"
phase=starting
sudo systemctl start "$service"
health || die "New service failed health or running executable verification."
trap - EXIT INT TERM
echo "Update successful. Running and installed executable match."
sha256sum "$built" "$binary"
echo "Refresh your browser. Reports and service configuration were not modified."
