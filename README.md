# Pulse

Pulse is a Wails desktop client for the mihomo/Clash.Meta core. The `main` branch is the Wails + React + Go client, while the `c` branch keeps the previous C/Android implementation.

## Preview

### Dashboard

The dashboard shows core status, realtime upload/download speed, total traffic, running time, and current mode in a compact overview.

![Pulse dashboard](img/1.png)

### Proxies

The proxy page lists Clash selector groups, node counts, current selections, and per-group delay testing.

![Pulse proxies](img/2.png)

### Profiles

The profiles page supports subscription import, local YAML drag-and-drop import, subscription usage display, provider updates, and proxy-based subscription updates.

![Pulse profiles](img/3.png)

## Features

- Embedded mihomo core mode and custom external core mode.
- Profile management for subscription URLs and local YAML files.
- Proxy group switching, node delay testing, provider updates, rules browsing, and connection management.
- Runtime settings for mixed port, secret, mode, Allow LAN, system proxy, subscription proxy, TUN, and log level.
- Custom background images with adjustable component opacity.
- Tray controls, single-instance handling, and `clash://install-config` URL import on Windows.
- GitHub release update checks and geodata fallback downloads.

## Core

Embedded mode runs mihomo inside Pulse. Custom mode can use an external mihomo binary path.

Pulse writes runtime overrides for:

- `mixed-port`
- `external-controller`
- `secret`
- `mode`
- `allow-lan`
- `tun`
- custom injected rules

## Development

```bash
wails dev
```

```bash
make build-windows
```

Other Makefile targets are available for Linux and macOS workflow builds.
