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
- `deb.afterInstall` / `deb.afterRemove` — custom postinst/postrm, see below

### The Chromium sandbox on Ubuntu 24.04+

Symptom, on the `.deb` and the AppImage alike:

```
FATAL:setuid_sandbox_host.cc(163)] The SUID sandbox helper binary was found, but
is not configured correctly. Rather than run without sandboxing I'm aborting now.
```

Chromium has two sandboxes: the namespace sandbox (unprivileged user
namespaces) and the older SUID helper. Ubuntu 24.04 shipped
`kernel.apparmor_restrict_unprivileged_userns=1`, which denies the first to
binaries with no AppArmor profile — so Electron falls back to the second, and
aborts if `chrome-sandbox` is not root-owned mode 4755.

**`.deb`.** electron-builder's stock postinst decides whether the SUID bit is
needed by running `unshare --user true`. A postinst runs as **root**, and the
AppArmor restriction applies to **unprivileged** namespaces only — so the probe
succeeds at install time, the postinst concludes the SUID helper is unnecessary,
and `chrome-sandbox` is installed 0755. The app then launches as an ordinary
user, is refused the namespace sandbox, falls back to the SUID helper, and dies.
`resources/after-install.sh` replaces that postinst: it installs an AppArmor
profile granting `userns create` (restoring the *namespace* sandbox, which is
the one upstream develops against) and probes as `nobody` rather than as root
when deciding the fallback.

**AppImage.** Not fixable from inside the artifact. An AppImage is a FUSE
squashfs mount, and FUSE mounts are `nosuid` — the SUID helper can never work
from one, whatever its mode bits say. There is also no install step in which to
place an AppArmor profile. Users on a restricted kernel need one of:

```bash
# Preferred: grant the namespace sandbox to AppImage mounts, keeping it enabled.
sudo tee /etc/apparmor.d/threatcrush-appimage >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>

profile threatcrush-appimage "/tmp/.mount_*/threatcrush-desktop" flags=(unconfined) {
  userns,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/threatcrush-appimage

# Or, to just get running — this turns the renderer sandbox off. For a security
# product that is a poor default, so prefer the profile above.
./threatcrush-desktop-*-x86_64.appimage --no-sandbox
```

Prefer the `.deb` on Ubuntu; it is the artifact that can fix itself at install
time.

## Known gaps

- macOS signing + notarization uses GitHub secrets (`APPLE_*`); missing secrets mean unsigned artifacts
- Windows signing likewise (`WINDOWS_CERTIFICATE`)
- Auto-update feed not configured
