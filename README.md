# Pulse

Pulse is now a Wails desktop client for the mihomo/Clash.Meta core.

## Branches

- `c`: preserved C/Android implementation.
- `main`: Wails + React + Go client.

## Core

Install a mihomo binary from MetaCubeX/mihomo and set its path in `设置 -> mihomo 路径`.

The app starts mihomo with the selected profile and writes Pulse runtime overrides for:

- `mixed-port`
- `external-controller`
- `secret`
- `mode`
- `allow-lan`
- `tun`

## Features

- Dashboard with core state, traffic, uptime, and recent logs.
- Profile management for subscription URLs and local YAML.
- Proxy group switching through the Clash REST API.
- Provider update, rules browsing, connection listing, and connection closing.
- Core settings, TUN toggle, LAN toggle, system proxy flag, and WebDAV setting storage.

## Development

```bash
wails dev
```

```bash
wails build
```
