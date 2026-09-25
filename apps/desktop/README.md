# @profullstack/threatcrush-desktop

Electron app that connects to a local `threatcrushd` over its Unix socket and shows live events / module state.

**Status:** public preview. Every `v*` tag publishes macOS (arm64 + x64 `.dmg`/`.zip`), Windows x64 (`-setup.exe`), Linux `.AppImage` and `.deb` to GitHub Releases. macOS and Windows builds are unsigned until the signing secrets exist (see [Signing](#signing)); the Linux builds are the most tested path.

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

### Runtime libraries

The Electron binary links `libgbm.so.1` and `libasound.so.2`. The `.deb`
declares `libgbm1` and `libasound2t64 | libasound2` (electron-builder's stock
`Depends:` omits both), so `apt install ./threatcrush-desktop-*.deb` pulls them
in. `libasound2t64` comes first because on Ubuntu 24.04+ a bare `libasound2`
can resolve to `liboss4-salsa-asound2`, which lacks ALSA symbols Electron
needs. The AppImage cannot declare anything: on a minimal system without them
it exits with `libgbm.so.1: cannot open shared object file`; install
`libgbm1` and `libasound2t64` (Ubuntu 24.04+/Debian 13) or `libasound2`
(older). Desktop installs already have both.

## Signing

`.github/workflows/desktop-release.yml` runs `scripts/desktop-signing-env.sh`,
which exports electron-builder's signing variables only for the secrets that
are set. With none set (today) the build is unsigned and the job summary says
so; nothing in `electron-builder.yml` needs to change once they are added.

| Secrets | Effect |
|---|---|
| `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD` | macOS app signed with the Developer ID Application identity (hardened runtime) |
| `APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER` (recommended) or `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` | the signed app is also notarized and stapled |
| `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD` | Windows installer and executables Authenticode-signed |

How to obtain each one: [`docs/DESKTOP_RELEASE_TODO.md`](../../docs/DESKTOP_RELEASE_TODO.md).

## Known gaps

- macOS/Windows builds unsigned until the secrets above exist
- No Linux arm64 or Windows arm64 builds
- Auto-update feed not configured
