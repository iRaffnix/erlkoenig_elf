#!/bin/sh
# erlkoenig_elf installer / updater
# ==================================
#
# Usage:
#   sudo sh install.sh --version v0.1.0          # download from GitHub
#   sudo sh install.sh --local /path/to/artifacts # install from local dir
#
# Installs to /opt/erlkoenig_elf. Symlinks systemd unit.
# Does NOT pipe curl into sh. Download, review, then run.

set -eu

REPO="iRaffnix/erlkoenig_elf"
PREFIX="/opt/erlkoenig_elf"
VERSION=""
LOCAL_DIR=""
FORCE=false

# ── Helpers ──────────────────────────────────────────────

info()  { echo "  [*] $*"; }
warn()  { echo "  [!] $*" >&2; }
err()   { echo "  [E] $*" >&2; }
ok()    { echo "  [+] $*"; }

# ── Argument parsing ─────────────────────────────────────

usage() {
    echo "Usage: sudo sh install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION   Download release from GitHub (e.g., v0.1.0)"
    echo "  --local DIR         Install from local directory (CI artifacts)"
    echo "  --prefix DIR        Installation directory (default: /opt/erlkoenig_elf)"
    echo "  --force             Force reinstall even if same version"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo sh install.sh --version v0.1.0"
    echo "  gh run download <run-id> -D /tmp/artifacts"
    echo "  sudo sh install.sh --local /tmp/artifacts"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --local)   LOCAL_DIR="$2"; shift 2 ;;
        --prefix)  PREFIX="$2"; shift 2 ;;
        --force)   FORCE=true; shift ;;
        --help|-h) usage ;;
        *)         err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Checks ───────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    err "Installer must be run as root (use sudo)"
    exit 1
fi

if [ -z "$VERSION" ] && [ -z "$LOCAL_DIR" ]; then
    err "--version or --local is required"
    echo "  Run: sh install.sh --help" >&2
    exit 1
fi

if [ -z "$LOCAL_DIR" ] && ! command -v curl >/dev/null 2>&1; then
    err "curl is required for remote install (or use --local)"
    exit 1
fi

if [ -n "$LOCAL_DIR" ] && [ ! -d "$LOCAL_DIR" ]; then
    err "Local directory not found: $LOCAL_DIR"
    exit 1
fi

# ── Hostname check ───────────────────────────────────────

if ! getent hosts "$(hostname)" >/dev/null 2>&1; then
    warn "Hostname '$(hostname)' not in /etc/hosts — remsh will fail"
    warn "Fix: echo '127.0.0.1 $(hostname)' >> /etc/hosts"
fi

# ── Detect architecture ─────────────────────────────────

detect_target() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) err "Unsupported architecture: $arch"; exit 1 ;;
    esac

    # Detect musl vs glibc
    libc="linux"
    if command -v ldd >/dev/null 2>&1; then
        if ldd --version 2>&1 | grep -qi musl; then
            libc="musl"
        fi
    elif [ -f /etc/alpine-release ]; then
        libc="musl"
    fi

    echo "${arch}-${libc}"
}

# ── Read installed version ───────────────────────────────

installed_version() {
    if [ -f "$PREFIX/releases/start_erl.data" ]; then
        awk '{print "v" $2}' "$PREFIX/releases/start_erl.data" 2>/dev/null || true
    fi
}

# ── Daemon management ────────────────────────────────────

daemon_is_running() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet erlkoenig_elf 2>/dev/null && return 0
    fi
    # Native Erlang-Ping-Prüfung via relx
    if [ -f "$PREFIX/cookie" ] && [ -x "$PREFIX/bin/erlkoenig_elf" ]; then
        RELX_COOKIE=$(cat "$PREFIX/cookie") "$PREFIX/bin/erlkoenig-elfd" ping >/dev/null 2>&1 && return 0
    fi
    return 1
}

stop_daemon() {
    info "Stopping erlkoenig_elf daemon ..."

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet erlkoenig_elf 2>/dev/null; then
        systemctl stop erlkoenig_elf 2>/dev/null || true
    fi

    if daemon_is_running; then
        # Sanfter Stop über relx
        if [ -f "$PREFIX/cookie" ] && [ -x "$PREFIX/bin/erlkoenig_elf" ]; then
            RELX_COOKIE=$(cat "$PREFIX/cookie") "$PREFIX/bin/erlkoenig-elfd" stop >/dev/null 2>&1 || true
        fi
    fi

    # Wait for clean shutdown (up to 15s — matches systemd TimeoutStopSec)
    i=0
    while [ $i -lt 15 ]; do
        if ! daemon_is_running; then
            ok "Daemon stopped"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done

    # Hartes Killen als allerletzter Ausweg
    pkill -9 -f "beam.*erlkoenig_elf" 2>/dev/null || true
    sleep 1
    ok "Daemon stopped (forced)"
}

start_daemon() {
    info "Starting erlkoenig_elf daemon ..."
    if command -v systemctl >/dev/null 2>&1 && [ -L /etc/systemd/system/erlkoenig_elf.service ]; then
        systemctl start erlkoenig_elf
    else
        # Start über relx als Daemon
        if [ -f "$PREFIX/cookie" ] && [ -x "$PREFIX/bin/erlkoenig_elf" ]; then
            RELX_COOKIE=$(cat "$PREFIX/cookie") "$PREFIX/bin/erlkoenig-elfd" daemon
        else
            warn "Could not start daemon manually: Binary or cookie missing."
        fi
    fi
    sleep 2
    if daemon_is_running; then
        ok "Daemon started"
    else
        warn "Daemon may not have started — check logs (e.g., journalctl -u erlkoenig_elf -n 20)"
    fi
}

# ── Version check ────────────────────────────────────────

TARGET=$(detect_target)
CURRENT=$(installed_version)
IS_UPDATE=false

if [ -d "$PREFIX/bin" ]; then
    IS_UPDATE=true
    if [ -n "$CURRENT" ] && [ -n "$VERSION" ]; then
        cur_norm=$(echo "$CURRENT" | sed 's/^v//')
        new_norm=$(echo "$VERSION" | sed 's/^v//')
        if [ "$cur_norm" = "$new_norm" ] && [ "$FORCE" = false ]; then
            ok "Already at version ${VERSION} — nothing to do (use --force to reinstall)"
            exit 0
        fi
    fi
fi

if [ "$IS_UPDATE" = true ]; then
    echo "Updating erlkoenig_elf: ${CURRENT:-unknown} -> ${VERSION:-local} (${TARGET})"
else
    echo "Installing erlkoenig_elf ${VERSION:-local} (${TARGET})"
fi
echo "  prefix: ${PREFIX}"
echo ""

# ── Stop daemon if running ───────────────────────────────

DAEMON_WAS_RUNNING=false

if [ "$IS_UPDATE" = true ] && daemon_is_running; then
    DAEMON_WAS_RUNNING=true
    stop_daemon
fi

# ── Acquire artifact ─────────────────────────────────────

TMPDIR=$(mktemp -d)
ARTIFACT=""

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if [ -n "$LOCAL_DIR" ]; then
    info "Installing from local artifacts: $LOCAL_DIR"
    ARTIFACT=$(find "$LOCAL_DIR" -name 'erlkoenig_elf-*.tar.gz' -print -quit 2>/dev/null || true)
    if [ -z "$ARTIFACT" ]; then
        err "No erlkoenig_elf-*.tar.gz found in $LOCAL_DIR"
        exit 1
    fi
    if [ -z "$VERSION" ]; then
        VERSION=$(tar xzf "$ARTIFACT" -O releases/start_erl.data 2>/dev/null | awk '{print "v"$2}' || true)
    fi
    ok "Found: $(basename "$ARTIFACT")"
else
    ARCHIVE="erlkoenig_elf-${VERSION}-${TARGET}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
    ARTIFACT="$TMPDIR/$ARCHIVE"

    info "Downloading ${ARCHIVE} ..."
    if ! curl -fsSL "$URL" -o "$ARTIFACT"; then
        err "Download failed. Check that ${VERSION} has a ${TARGET} build."
        err "Available at: https://github.com/${REPO}/releases/tag/${VERSION}"
        if [ "$DAEMON_WAS_RUNNING" = true ]; then
            warn "Restarting daemon with previous version ..."
            start_daemon
        fi
        exit 1
    fi
fi

# Verify archive
if ! tar tzf "$ARTIFACT" >/dev/null 2>&1; then
    err "Release archive is corrupt"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

ok "Artifact verified"

# ── Preserve cookie before extraction ────────────────────

if [ "$IS_UPDATE" = true ] && [ -f "$PREFIX/cookie" ]; then
    cp "$PREFIX/cookie" "$TMPDIR/cookie.preserve"
fi

# ── Extract ──────────────────────────────────────────────

mkdir -p "$PREFIX"

info "Extracting to ${PREFIX} ..."
if ! tar xzf "$ARTIFACT" -C "$PREFIX"; then
    err "Extraction failed"
    if [ "$DAEMON_WAS_RUNNING" = true ]; then
        warn "Restarting daemon with previous version ..."
        start_daemon
    fi
    exit 1
fi

# Restore preserved cookie
if [ -f "$TMPDIR/cookie.preserve" ]; then
    cp "$TMPDIR/cookie.preserve" "$PREFIX/cookie"
    ok "Cookie preserved"
fi

# ── File permissions ─────────────────────────────────────

chown -R root:root "$PREFIX"
chmod 755 "$PREFIX"
[ -f "$PREFIX/bin/erlkoenig_elf" ] && chmod 755 "$PREFIX/bin/erlkoenig_elf"
[ -f "$PREFIX/bin/erlkoenig-elf" ] && chmod 755 "$PREFIX/bin/erlkoenig-elf"
[ -f "$PREFIX/dist/erlkoenig_elf.service" ] && chmod 644 "$PREFIX/dist/erlkoenig_elf.service"

ok "Permissions set"

# ── Symlink erlkoenig-elfd → erlkoenig_elf (daemon) ─────

if [ -f "$PREFIX/bin/erlkoenig_elf" ] && [ ! -e "$PREFIX/bin/erlkoenig-elfd" ]; then
    ln -s erlkoenig_elf "$PREFIX/bin/erlkoenig-elfd"
    ok "Daemon symlink: bin/erlkoenig-elfd → erlkoenig_elf"
fi

# ── Fix escript shebang to use bundled ERTS ──────────────

ERTS_BIN=$(ls -d "$PREFIX"/erts-*/bin 2>/dev/null | head -1)
if [ -n "$ERTS_BIN" ] && [ -f "$PREFIX/bin/erlkoenig-elf" ]; then
    sed -i "1s|.*|#!${ERTS_BIN}/escript|" "$PREFIX/bin/erlkoenig-elf"
    ok "CLI shebang: ${ERTS_BIN}/escript"
fi

# ── Generate cookie (first install only) ─────────────────

if [ ! -f "$PREFIX/cookie" ]; then
    head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32 > "$PREFIX/cookie"
    ok "Cookie generated"
fi
chmod 400 "$PREFIX/cookie"

# ── Systemd symlink ──────────────────────────────────────

if [ -d /etc/systemd/system ]; then
    ln -sf "$PREFIX/dist/erlkoenig_elf.service" /etc/systemd/system/erlkoenig_elf.service
    systemctl daemon-reload
    ok "Systemd unit: erlkoenig_elf.service (symlinked)"
fi

# ── Restart daemon if it was running ─────────────────────

if [ "$DAEMON_WAS_RUNNING" = true ]; then
    start_daemon
fi

# ── Done ─────────────────────────────────────────────────

echo ""
if [ "$IS_UPDATE" = true ]; then
    echo "Update complete! ${CURRENT:-unknown} -> ${VERSION:-local}"
else
    echo "Installation complete!"
fi
echo ""
echo "  Start:     sudo systemctl start erlkoenig_elf"
echo "  Status:    sudo systemctl status erlkoenig_elf"
echo "  Stop:      sudo systemctl stop erlkoenig_elf"
echo "  Enable:    sudo systemctl enable erlkoenig_elf"
echo "  Logs:      journalctl -u erlkoenig_elf -f"
echo "  Shell:     sudo ERL_DIST_PORT=9103 RELX_COOKIE=\$(cat $PREFIX/cookie) $PREFIX/bin/erlkoenig-elfd remote_console"
echo ""
echo "  Config:    $PREFIX/config/sys.config"
echo "  Socket:    /run/erlkoenig_elf/ctl.sock"
echo ""
if [ "$IS_UPDATE" = false ]; then
    echo "  NOTE: Review config before starting. See ARCHITECTURE.md for details."
fi
