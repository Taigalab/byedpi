#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# install.sh - Detect the distribution's package manager, install every build
# and runtime dependency, then build and (optionally) install Passewall.
#
# Usage:
#   ./install.sh            # install deps, build, and `meson install`
#   ./install.sh --no-gui   # build the headless binary only
#   ./install.sh --build-only   # skip system installation

set -euo pipefail

GUI=true
DO_INSTALL=true

for arg in "$@"; do
    case "$arg" in
        --no-gui)     GUI=false ;;
        --build-only) DO_INSTALL=false ;;
        -h|--help)
            echo "Usage: $0 [--no-gui] [--build-only]"
            exit 0 ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2 ;;
    esac
done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Elevate a command with sudo when not already root.
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "need root privileges (install sudo or run as root) to: $*"
    fi
}

detect_pm() {
    if command -v apt-get >/dev/null 2>&1; then echo apt
    elif command -v pacman >/dev/null 2>&1; then echo pacman
    elif command -v dnf   >/dev/null 2>&1; then echo dnf
    elif command -v zypper >/dev/null 2>&1; then echo zypper
    else echo unknown
    fi
}

install_deps() {
    local pm="$1"
    case "$pm" in
    apt)
        log "Installing dependencies with apt"
        as_root apt-get update
        local pkgs=(build-essential meson ninja-build pkg-config \
                    libnetfilter-queue-dev iptables)
        if $GUI; then
            pkgs+=(libgtk-4-dev libadwaita-1-dev)
        fi
        as_root apt-get install -y "${pkgs[@]}"
        ;;
    pacman)
        log "Installing dependencies with pacman"
        local pkgs=(base-devel meson ninja pkgconf libnetfilter_queue iptables)
        if $GUI; then
            pkgs+=(gtk4 libadwaita)
        fi
        as_root pacman -Sy --needed --noconfirm "${pkgs[@]}"
        ;;
    dnf)
        log "Installing dependencies with dnf"
        local pkgs=(gcc meson ninja-build pkgconf-pkg-config \
                    libnetfilter_queue-devel iptables)
        if $GUI; then
            pkgs+=(gtk4-devel libadwaita-devel)
        fi
        as_root dnf install -y "${pkgs[@]}"
        ;;
    zypper)
        log "Installing dependencies with zypper"
        local pkgs=(gcc meson ninja pkg-config \
                    libnetfilter_queue-devel iptables)
        if $GUI; then
            pkgs+=(gtk4-devel libadwaita-devel)
        fi
        as_root zypper install -y "${pkgs[@]}"
        ;;
    *)
        die "unsupported distribution: install meson, ninja, pkg-config, a C
compiler, libnetfilter-queue (dev), iptables and (for the GUI) GTK4 +
libadwaita manually, then run: meson setup build && ninja -C build"
        ;;
    esac
}

main() {
    local pm
    pm="$(detect_pm)"
    [ "$pm" = unknown ] && die "could not detect a supported package manager"
    log "Detected package manager: $pm"

    install_deps "$pm"

    log "Configuring build (gui=$GUI)"
    meson setup build --prefix=/usr/local -Dgui="$GUI" --wipe 2>/dev/null \
        || meson setup build --prefix=/usr/local -Dgui="$GUI"

    log "Compiling"
    ninja -C build

    if $DO_INSTALL; then
        log "Installing system-wide"
        as_root ninja -C build install
        log "Done. Launch the GUI with:  sudo passewall"
        log "Or run headless with:        sudo passewall --no-gui"
    else
        log "Build complete: ./build/passewall"
        log "Run it with:    sudo ./build/passewall"
    fi
}

main "$@"
