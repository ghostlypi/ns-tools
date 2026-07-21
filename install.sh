#!/usr/bin/env bash
#
# netdrop installer — builds nsen + netdrop from a cloned checkout and sets up
# the AirDrop-like receiver on THIS device: binaries, the Nautilus "Send with
# netdrop" menu, and a background systemd user service that makes the device
# discoverable and shows the Accept/Reject prompt.
#
# The device advertises under its GNOME "Device Name" (Settings → About)
# automatically — no name needs to be set.
#
# Usage:
#   ./install.sh                             # build + install + enable
#   NETDROP_NAME="Kitchen Pi" ./install.sh   # optional: override the device name
#   PREFIX=/usr/bin ./install.sh             # install binaries somewhere else
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local/bin}"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$REPO_DIR/Cargo.toml" ] || die "run this from the cloned nsen repo"

# ── 1. Dependencies ──────────────────────────────────────────────────────────
# Build deps: cargo, a C compiler, and the system OpenSSL (we build against it
# with OPENSSL_NO_VENDOR=1 to avoid the vendored-OpenSSL Perl toolchain).
# Runtime deps: nautilus-python + gi bindings (menu), zenity (dialog),
# libnotify (toasts).
if command -v dnf >/dev/null 2>&1; then
    log "Installing dependencies with dnf…"
    sudo dnf install -y \
        cargo gcc pkgconf-pkg-config openssl-devel \
        nautilus-python python3-gobject zenity libnotify
elif command -v apt-get >/dev/null 2>&1; then
    log "Installing dependencies with apt…"
    sudo apt-get update
    sudo apt-get install -y \
        cargo gcc pkg-config libssl-dev \
        python3-nautilus python3-gi zenity libnotify-bin
else
    warn "no dnf/apt found — install these yourself before continuing:"
    warn "  build: cargo, gcc, pkg-config, openssl headers"
    warn "  run:   nautilus-python, python3 gobject bindings, zenity, libnotify"
fi

command -v cargo >/dev/null 2>&1 || die "cargo not found (install Rust: https://rustup.rs)"

# ── 2. Build ─────────────────────────────────────────────────────────────────
log "Building nsen + netdrop (release)…"
cd "$REPO_DIR"
OPENSSL_NO_VENDOR=1 cargo build --release --workspace \
    || die "build failed — if it mentions edition 2024, your Rust is too old; install a newer toolchain via https://rustup.rs"

# ── 3. Install binaries ──────────────────────────────────────────────────────
log "Installing binaries to $PREFIX…"
sudo install -Dm755 target/release/nsen    "$PREFIX/nsen"
sudo install -Dm755 target/release/netdrop "$PREFIX/netdrop"

# ── 4. Nautilus extension (per-user) ─────────────────────────────────────────
log "Installing the Nautilus extension…"
install -Dm644 packaging/netdrop.py \
    "$HOME/.local/share/nautilus-python/extensions/netdrop.py"

# ── 5. Optional friendly name ────────────────────────────────────────────────
if [ -n "${NETDROP_NAME:-}" ]; then
    log "Setting device name: $NETDROP_NAME"
    mkdir -p "$HOME/.config/nsen"
    printf '%s\n' "$NETDROP_NAME" > "$HOME/.config/nsen/name"
fi

# ── 6. systemd user service (the always-on receiver) ─────────────────────────
# Point ExecStart at wherever we installed the binary, then import the
# graphical-session env so the daemon can pop the zenity dialog.
log "Installing + (re)starting the netdrop receiver service…"
mkdir -p "$HOME/.config/systemd/user"
sed "s#/usr/bin/netdrop#$PREFIX/netdrop#" packaging/netdrop.service \
    > "$HOME/.config/systemd/user/netdrop.service"
systemctl --user daemon-reload
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS 2>/dev/null || true
# `enable` (start at login) + `restart` (start now, or swap the binary if this is
# a re-run/update — `enable --now` alone would leave an old daemon running).
systemctl --user enable netdrop.service
systemctl --user restart netdrop.service

# ── 7. Firewall (so discovery + transfers get through) ───────────────────────
# mDNS is UDP 5353; the control/data ports are TCP 4445/4444.
if command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --state >/dev/null 2>&1; then
    log "Opening firewall for mDNS (5353/udp) and transfers (4444-4445/tcp)…"
    sudo firewall-cmd --permanent --add-service=mdns              >/dev/null || true
    sudo firewall-cmd --permanent --add-port=4444-4445/tcp        >/dev/null || true
    sudo firewall-cmd --reload                                    >/dev/null || true
else
    warn "no active firewalld detected — if devices can't see each other, allow"
    warn "  UDP 5353 (mDNS) and TCP 4444-4445 in your firewall."
fi

# ── 8. Reload Nautilus so the menu appears ───────────────────────────────────
nautilus -q >/dev/null 2>&1 || true

NAME="$(cat "$HOME/.config/nsen/name" 2>/dev/null || hostname)"
log "Done. This device is discoverable as: $NAME"
cat <<EOF

  Check it's running:   systemctl --user status netdrop.service
  See nearby devices:   netdrop discover
  Send a file:          netdrop send "<device name>" <file>
                        …or right-click a file in Files → "Send with netdrop"

Run install.sh on your other device too, then send between them.
EOF
