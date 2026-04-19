# @profullstack/threatcrush-desktop

Electron app that connects to a local `threatcrushd` over its Unix socket and shows live events / module state.

**Status:** public preview. macOS and Windows builds aren't signed yet — the Linux `.AppImage` and `.deb` artifacts produced by CI are the most tested path.

## Dev

```bash
# from repo root
pnpm install
pnpm --filter @profullstack/threatcrush-desktop dev   # electron-vite dev
```

## Build

```bash
pnpm --filter @profullstack/threatcrush-desktop build     # electron-vite → out/
pnpm --filter @profullstack/threatcrush-desktop package:linux
pnpm --filter @profullstack/threatcrush-desktop package:mac
pnpm --filter @profullstack/threatcrush-desktop package:win
```

Packaged artifacts land in `apps/desktop/release/`.

## IPC architecture

The renderer never talks to the daemon directly. Flow:

```
renderer  →  window.api.*     (preload/index.ts)
         →  ipcMain.handle    (main/index.ts)
         →  DaemonClient      (main/daemon-client.ts)
         →  /var/run/threatcrush/threatcrushd.sock   (Unix socket, JSON lines)
```

The main process opens the socket, subscribes to `event` + `module` push channels, and re-broadcasts them to the renderer as `threat-event` messages.

## Preload API

Exposed as `window.api`:

- `connectDaemon(socketPath?)` — connect; legacy `(host, port)` signature also accepted and ignored
- `disconnectDaemon()`
- `daemonStatus()` — returns `{ running, pid, uptimeSeconds, modules }`
- `daemonRequest(method, params)` — low-level JSON-RPC passthrough
- `onEvent(cb)` — subscribe to pushed frames; returns an unsubscribe fn

## Packaging notes

`electron-builder.yml`:

- `npmRebuild: false` — pnpm symlinks confuse `@electron/rebuild`; we have no native deps anyway
- `executableName: threatcrush-desktop` — avoids fpm tripping on the scoped `@profullstack/` name
- `directories.output: release`

## Known gaps

- macOS signing + notarization uses GitHub secrets (`APPLE_*`); missing secrets mean unsigned artifacts
- Windows signing likewise (`WINDOWS_CERTIFICATE`)
- Auto-update feed not configured
