#!/usr/bin/env bash
# Install with:
# curl -fsSL https://raw.githubusercontent.com/arefhere51/mozvps/main/install.sh | sudo bash
# Only this installer, the server entry point, and the declared Python
# dependencies are executed; no downloaded setup/update shell script is run.
set -Eeuo pipefail
umask 022

readonly REPOSITORY='https://github.com/arefhere51/mozvps'
readonly BRANCH='main'
readonly TARGET='/opt/mozvps'
readonly DATA='/var/lib/mozvps'
readonly UNIT='/etc/systemd/system/mozvps.service'
readonly LAUNCHER='/usr/local/bin/mozvps'
readonly SERVICE='mozvps.service'
readonly MARKER='mozvps-managed-deployment-v1'

mode=install
if (( $# > 1 )); then
    printf 'Usage: install.sh [--update]\n' >&2; exit 2
elif (( $# == 1 )); then
    [[ $1 == --update ]] || { printf 'Usage: install.sh [--update]\n' >&2; exit 2; }
    mode=update
fi

say() { printf '\n[mozvps] %s\n' "$*"; }
die() { printf '\n[mozvps] ERROR: %s\n' "$*" >&2; exit 1; }

work=''
backup=''
transaction=0
old_moved=0
published=0
had_unit=0
had_launcher=0
was_active=0
was_enabled=0

# All backups are outside the temporary staging directory: even a failed
# rollback must not delete either the old deployment or the failed candidate.
rollback() {
    local failed=''
    printf '[mozvps] Restoring the previous deployment; persistent data is untouched.\n' >&2
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    if (( published )) && [[ -d $TARGET && ! -L $TARGET ]]; then
        failed=$(mktemp -d /opt/.mozvps-failed.XXXXXX) && rmdir "$failed" && mv -- "$TARGET" "$failed"
        if [[ -n $failed && -d $failed ]]; then
            printf '[mozvps] Failed candidate retained at %s\n' "$failed" >&2
        else
            printf '[mozvps] WARNING: could not move the failed candidate away from %s.\n' "$TARGET" >&2
        fi
    fi
    if (( old_moved )); then
        if [[ ! -e $TARGET && ! -L $TARGET ]]; then
            mv -- "$backup" "$TARGET" || printf '[mozvps] WARNING: restore %s manually to %s.\n' "$backup" "$TARGET" >&2
        else
            printf '[mozvps] WARNING: old deployment remains at %s; restore it manually.\n' "$backup" >&2
        fi
    fi
    if (( had_unit )); then
        cp -a -- "$work/old-unit" "$UNIT.rollback.$$" && mv -Tf -- "$UNIT.rollback.$$" "$UNIT" || printf '[mozvps] WARNING: could not restore the old service unit.\n' >&2
    else
        rm -f -- "$UNIT"
    fi
    if (( had_launcher )); then
        cp -a -- "$work/old-launcher" "$LAUNCHER.rollback.$$" && mv -Tf -- "$LAUNCHER.rollback.$$" "$LAUNCHER" || printf '[mozvps] WARNING: could not restore the old launcher.\n' >&2
    else
        rm -f -- "$LAUNCHER"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || printf '[mozvps] WARNING: systemd reload failed during rollback.\n' >&2
    if (( was_enabled )); then
        systemctl enable "$SERVICE" >/dev/null 2>&1 || printf '[mozvps] WARNING: failed to restore enablement.\n' >&2
    fi
    if (( was_active )); then
        systemctl start "$SERVICE" >/dev/null 2>&1 || printf '[mozvps] WARNING: failed to restart the previous service.\n' >&2
    fi
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    set +e
    if (( rc != 0 && transaction )); then rollback; fi
    [[ -z $work || ! -d $work ]] || rm -rf -- "$work"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

(( EUID == 0 )) || die 'Run as root: curl -fsSL https://raw.githubusercontent.com/arefhere51/mozvps/main/install.sh | sudo bash'
[[ -r /etc/os-release ]] || die 'Cannot identify the Linux distribution.'
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *' debian '*|*' ubuntu '*) ;;
    *) die 'Only Debian/Ubuntu and compatible apt-based systems are supported.' ;;
esac
command -v apt-get >/dev/null 2>&1 || die 'apt-get was not found.'
command -v systemctl >/dev/null 2>&1 || die 'systemctl was not found.'
[[ -d /run/systemd/system ]] || die 'A running systemd system manager is required.'
command -v flock >/dev/null 2>&1 || die 'flock (util-linux) is required.'
mkdir -p /run/lock /opt
exec 9>/run/lock/mozvps-install.lock
flock -n 9 || die 'Another MozVPS installation or update is in progress.'

# Refuse to take over unknown installations or symlinked deployment targets.
for path in "$TARGET" "$UNIT" "$LAUNCHER" "$DATA"; do
    [[ ! -L $path ]] || die "Refusing symlinked deployment path: $path"
done
if [[ -e $TARGET ]]; then
    [[ -d $TARGET && -f $TARGET/.mozvps-managed && ! -L $TARGET/.mozvps-managed ]] || die "$TARGET is not a managed MozVPS deployment; refusing to replace it."
    [[ $(cat "$TARGET/.mozvps-managed") == "$MARKER" ]] || die 'Unrecognized deployment marker; refusing to replace the existing files.'
elif [[ $mode == update ]]; then
    die 'No managed installation was found. Run the installation command first.'
elif [[ -e $UNIT || -e $LAUNCHER ]]; then
    die 'An existing service or launcher is unmanaged; refusing to replace it.'
fi
[[ ! -e $UNIT || -f $UNIT ]] || die "$UNIT is not a regular file."
[[ ! -e $LAUNCHER || -f $LAUNCHER ]] || die "$LAUNCHER is not a regular file."
[[ ! -e $DATA || -d $DATA ]] || die "$DATA is not a directory."

say 'Installing system prerequisites (git, Python, venv and native-build libraries).'
export DEBIAN_FRONTEND=noninteractive
apt-get update </dev/null
apt-get install -y --no-install-recommends \
    ca-certificates curl git python3 python3-venv python3-dev \
    build-essential pkg-config libssl-dev libffi-dev zlib1g-dev libjpeg-dev </dev/null

# The worker prefers sing-box for HTTP/2/HTTP/3 data-plane transport. Resolve
# the current upstream Linux asset by architecture instead of pinning a stale
# release URL into the installer.
if ! command -v sing-box >/dev/null 2>&1; then
    say 'Installing sing-box transport engine.'
    sb_arch=$(case "$(uname -m)" in
        x86_64|amd64) printf 'amd64';;
        aarch64|arm64) printf 'arm64';;
        armv7l|armv7) printf 'armv7';;
        *) die "Unsupported sing-box architecture: $(uname -m)";;
    esac)
    sb_url=$(python3 - "$sb_arch" <<'PY'
import json, sys, urllib.request
arch = sys.argv[1]
req = urllib.request.Request(
    'https://api.github.com/repos/SagerNet/sing-box/releases/latest',
    headers={'User-Agent': 'mozvps-installer'})
with urllib.request.urlopen(req, timeout=20) as response:
    release = json.load(response)
for asset in release.get('assets', []):
    name = asset.get('name', '')
    if name.endswith('.tar.gz') and ('linux-' + arch) in name and 'amd64v3' not in name:
        print(asset['browser_download_url'])
        break
else:
    raise SystemExit('No sing-box Linux asset found for ' + arch)
PY
)
    sb_tmp=$(mktemp -d /tmp/mozvps-singbox.XXXXXX)
    curl -fsSL --retry 3 "$sb_url" -o "$sb_tmp/sing-box.tar.gz"
    tar -xzf "$sb_tmp/sing-box.tar.gz" -C "$sb_tmp"
    sb_bin=$(find "$sb_tmp" -type f -name sing-box -perm -u+x -print -quit)
    [[ -n $sb_bin ]] || die 'Downloaded sing-box archive did not contain an executable.'
    install -o root -g root -m 0755 "$sb_bin" /usr/local/bin/sing-box
    rm -rf "$sb_tmp"
fi

# A private HOME and disabled Git system configuration prevent user-configured
# insteadOf rewrites, credentials and hooks from redirecting the fixed URL.
work=$(mktemp -d /opt/.mozvps-stage.XXXXXX)
mkdir -m 0700 "$work/git-home"
say "Cloning only $REPOSITORY (branch $BRANCH)."
env -i HOME="$work/git-home" PATH=/usr/bin:/bin LANG=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null \
    -c credential.helper= -c http.followRedirects=false \
    -c protocol.file.allow=never clone --depth 1 --single-branch \
    --no-tags --branch "$BRANCH" "$REPOSITORY" "$work/source" </dev/null

# Do not assume the requested branch contains the panel or deployment files.
for rel in server.py worker.py auth_helper.py mozvpn.py requirements.txt install.sh \
    bin/mozvps deploy/mozvps.service ui/index.html ui/app.js ui/style.css; do
    file="$work/source/$rel"
    [[ -f $file && ! -L $file ]] || die "Repository $BRANCH is missing a regular file: $rel"
    resolved=$(realpath -e -- "$file")
    [[ $resolved == "$work/source/"* ]] || die "Unsafe path in repository: $rel"
done
[[ ! -e $work/source/venv && ! -L $work/source/venv ]] || die 'The repository must not contain a venv directory.'
[[ ! -e $work/source/.mozvps-managed && ! -L $work/source/.mozvps-managed ]] || die 'The repository contains a reserved deployment marker.'
bash -n "$work/source/install.sh"
bash -n "$work/source/bin/mozvps"
PYTHONPYCACHEPREFIX="$work/pycache" python3 -m py_compile \
    "$work/source/server.py" "$work/source/worker.py" "$work/source/auth_helper.py" "$work/source/mozvpn.py"

# Refuse extra systemd command hooks or changed service identities. The only
# upstream program systemd will start is the explicitly requested server.py.
awk '
  /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
  /^[[:space:]]*\[/ { in_service=($0 ~ /^[[:space:]]*\[Service\][[:space:]]*$/); next }
  in_service && /=/ {
    line=$0; sub(/^[[:space:]]*/, "", line)
    key=line; sub(/=.*/, "", key); sub(/[[:space:]]*$/, "", key)
    value=line; sub(/^[^=]*=/, "", value)
    sub(/^[[:space:]]*/, "", value); sub(/[[:space:]]*$/, "", value)
    if (key ~ /^Exec/) {
      if (key != "ExecStart" || value != "/opt/mozvps/venv/bin/python /opt/mozvps/server.py") bad=1
      else execs++
    }
    if (key == "User") { if (value != "mozvps") bad=1; users++ }
    if (key == "Group") { if (value != "mozvps") bad=1; groups++ }
    if (key == "WorkingDirectory") { if (value != "/opt/mozvps") bad=1; dirs++ }
    if (key == "KillMode") { if (value != "control-group") bad=1; killmodes++ }
    if (key == "EnvironmentFile") bad=1
    if (key == "Environment" && value ~ /MOZVPS_DATA=/) {
      if (value != "MOZVPS_DATA=/var/lib/mozvps") bad=1
      else data++
    }
  }
  END { if (bad || execs != 1 || users != 1 || groups != 1 || dirs != 1 || killmodes != 1 || data != 1) exit 1 }
' "$work/source/deploy/mozvps.service" || die 'Repository systemd unit does not match the safe deployment contract.'

say 'Preflighting Python dependencies before touching the running service.'
python3 -m venv "$work/check-venv"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$work/check-venv/bin/python" -m pip install -r "$work/source/requirements.txt" </dev/null
"$work/check-venv/bin/python" -m pip check

if ! getent group mozvps >/dev/null; then groupadd --system mozvps; fi
if ! getent passwd mozvps >/dev/null; then
    useradd --system --gid mozvps --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin mozvps
fi
service_uid=$(id -u mozvps)
(( service_uid != 0 )) || die 'The existing mozvps account has UID 0; refusing to use it.'
if [[ -d $DATA ]]; then
    [[ $(stat -c %u "$DATA") == "$service_uid" ]] || die "$DATA already exists and has a different owner; refusing to alter existing data."
    chgrp mozvps "$DATA"
    chmod 0700 "$DATA"
else
    install -d -o mozvps -g mozvps -m 0700 "$DATA"
fi

# Save service and launcher files and prior state before any publication.
mkdir -p /etc/systemd/system /usr/local/bin
if [[ -f $UNIT ]]; then cp -a -- "$UNIT" "$work/old-unit"; had_unit=1; fi
if [[ -f $LAUNCHER ]]; then cp -a -- "$LAUNCHER" "$work/old-launcher"; had_launcher=1; fi
if systemctl is-active --quiet "$SERVICE"; then was_active=1; fi
if systemctl is-enabled --quiet "$SERVICE"; then was_enabled=1; fi

# The service sees no code changes until staging and dependency preflight pass.
transaction=1
if (( was_active )); then
    say 'Stopping the current service before replacing its code.'
    systemctl stop "$SERVICE"
fi
if [[ -d $TARGET ]]; then
    backup=$(mktemp -d /opt/.mozvps-backup.XXXXXX)
    rmdir "$backup"
    mv -- "$TARGET" "$backup"
    old_moved=1
fi
mv -- "$work/source" "$TARGET"
published=1
printf '%s\n' "$MARKER" > "$TARGET/.mozvps-managed"
chown -R root:root "$TARGET"
chmod -R go-w "$TARGET"
chmod 0755 "$TARGET"

# A venv is not relocatable: create it at its final path instead of moving the
# preflight venv. This also keeps all installed executable shebangs correct.
say 'Creating the final virtual environment and installing dependencies.'
python3 -m venv "$TARGET/venv"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$TARGET/venv/bin/python" -m pip install -r /opt/mozvps/requirements.txt </dev/null
"$TARGET/venv/bin/python" -m pip check
chmod -R go-w "$TARGET/venv"

# Replace files atomically so an already-running launcher remains readable.
install -o root -g root -m 0644 "$TARGET/deploy/mozvps.service" "$UNIT.new.$$"
mv -Tf -- "$UNIT.new.$$" "$UNIT"
install -o root -g root -m 0755 "$TARGET/bin/mozvps" "$LAUNCHER.new.$$"
mv -Tf -- "$LAUNCHER.new.$$" "$LAUNCHER"
if command -v systemd-analyze >/dev/null 2>&1; then systemd-analyze verify "$UNIT"; fi
systemctl daemon-reload
systemctl enable "$SERVICE"
if [[ $mode == install ]] || (( was_active )); then
    systemctl restart "$SERVICE"
    sleep 2
    systemctl is-active --quiet "$SERVICE" || die 'The service did not stay active after startup; rolling back.'
else
    say 'The service was stopped before the update and remains stopped.'
fi
transaction=0

say 'Installation/update completed. Service is enabled at boot.'
if (( old_moved )); then
    printf '[mozvps] Previous deployment retained at %s (remove manually when no longer needed).\n' "$backup"
fi
printf '[mozvps] Persistent data: %s (owned by mozvps, mode 0700).\n' "$DATA"
printf '[mozvps] Commands: mozvps  |  mozvps status  |  mozvps logs  |  mozvps info\n'
printf '[mozvps] Panel default: http://<SERVER-IP>:1234/ (binds 0.0.0.0).\n'
printf '[mozvps] Initial admin password: admin. Change it immediately; existing passwords are retained.\n'
printf '[mozvps] HTTP is not encrypted. Restrict access and use HTTPS or an SSH tunnel.\n'
