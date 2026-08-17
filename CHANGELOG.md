# Changelog

All notable changes to ByeDPI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-17

Initial release.

### Added

- **Packet engine** built on `libnetfilter_queue` (queue number 100). On
  start it installs `iptables` (and, unless `--no-ipv6`, `ip6tables`) NFQUEUE
  rules for TCP 80/443 and UDP 53/443, and removes exactly those rules on exit
  (SIGINT/SIGTERM) or when the bypass is toggled off.
- **DPI evasion**, equivalent to GoodbyeDPI's combined `-5` mode:
  - TCP fragmentation of the first application data segment.
  - Low-TTL fake duplicate packet injected before the real data.
  - HTTP `Host` header fragmentation across two TCP segments.
  - TLS ClientHello splitting at the SNI boundary.
  - DNS interception and forwarding to a configurable upstream resolver
    (`1.1.1.1` by default) with a fallback (`8.8.8.8`), returning the answer to
    the originating process.
  - QUIC/HTTP3 awareness: QUIC Initial packets on UDP 443 can be dropped to
    force a TCP/TLS fallback that the TCP path defeats.
- **Environment detection**: warns when `ufw` or `firewalld` are active and
  notes when `systemd-resolved` occupies port 53 (DNS is then forwarded from an
  ephemeral local port to avoid a bind conflict).
- **GTK4 + libadwaita GUI**:
  - Master DPI Bypass switch with a coloured status indicator.
  - DNS upstream selector (Cloudflare / Google / custom).
  - Fake-TTL slider (1–10, default 5).
  - Toggles for HTTP splitting, HTTPS/SNI splitting, DNS interception, and
    QUIC/HTTP3.
  - Verbose logging toggle with an expandable, terminal-style live log.
  - IPv6 toggle, "Run on login", and "Start minimized to tray".
- **System tray** implemented as a freedesktop StatusNotifierItem with a
  DBusMenu context menu (Enable/Disable, Open Window, Quit). The tray icon
  colour reflects the active/inactive state.
- **CLI modes**: full GUI (default), `--no-gui` (headless), and `--tray`
  (tray only). Flags: `--dns-addr`, `--ttl`, `--no-ipv6`, `--verbose`.
- **Autostart** management writing/removing
  `~/.config/autostart/io.github.byedpi.ByeDPI.desktop`, honoring the
  "start minimized to tray" preference.
- **Distribution**: Meson build system, a Makefile wrapper, an `install.sh`
  that auto-detects apt/pacman/dnf/zypper, a Flatpak manifest, a `.desktop`
  entry, and AppStream metainfo.

[0.1.0]: https://github.com/TaigaLinux/byedpi/releases/tag/v0.1.0
