# ThreatCrush Surfaces

Last updated: 2026-09-25 (release rows checked against `gh run list`, `gh release view v0.13.7`, npm and GHCR)

Two axes, tracked separately on purpose. **Interfaces** are what users touch.
**Distribution channels** are how they get them.

Status values:

| Value | Meaning |
|---|---|
| `shipping` | Tagged, published, supported |
| `preview` | Built and functional, not on the happy path yet |
| `alpha` | Runs, but breaking changes expected |
| `deferred` | Not in v0.1.0 — intentionally cut |
| `not-started` | No code written |

---

## Interfaces

| Interface | Status | Repo path | Primary channels | Notes |
|---|---|---|---|---|
| **PWA / Web** | `shipping` | `apps/web/` | Railway → [threatcrush.com](https://threatcrush.com), Docker image | Next.js 16, Supabase, Tailwind 4. `output: standalone`. |
| **CLI** | `shipping` | `apps/cli/` | npm (`@profullstack/threatcrush`), `curl \| sh` | v0.13.7 on npm. `threatcrushd` daemon, IPC socket, systemd unit. |
| **TUI** | `shipping` | `apps/cli/src/tui/` | Bundled with CLI | `@profullstack/hqtui` dashboard, live over daemon IPC. `threatcrush tui` (add `--demo` for canned events). |
| **API** | `shipping` | `apps/web/src/app/api/` | Same origin as web | REST, bearer-token auth. Used by CLI, desktop, extension. |
| **Webhooks (outbound)** | `shipping` | `apps/cli/src/daemon/alerts/` | Slack, generic webhook | Threat alerts emit when severity ≥ high. |
| **Email (outbound)** | `shipping` | `apps/cli/src/daemon/alerts/smtp.ts` | SMTP via `nodemailer` | Configure `[alerts.email]` in `threatcrushd.conf`. |
| **Desktop** | `preview` | `apps/desktop/` | GitHub Releases (macOS/Windows unsigned) | Electron. IPC bridge to local `threatcrushd` via Unix socket. Every tag since v0.13.2 publishes macOS arm64/x64, Windows x64, AppImage and .deb; the Linux builds start and render under Xvfb. The dashboard still streams generated demo events (`generateFakeEvent` in `StatsBar.tsx`) whether or not a daemon is connected, and the sidebar shows a hard-coded `v0.1.3`. |
| **Browser extension** | `preview` | `apps/extension/` | Sideload from source | Vite + React 19 + MV3. Store submissions post-v0.1.0. |
| **SDK** | `alpha` | `apps/sdk/` | npm (`@threatcrush/sdk`), not published (npm 404) | Types for module authors. `npm-publish.yml` publishes only the CLI. |
| **Plugin / integration** | `preview` | `apps/cli/src/daemon/module-host.ts`, `apps/web/src/app/store/` | Module marketplace ([threatcrush.com/store](https://threatcrush.com/store), `/api/modules`) | 10 listed modules, all free. `threatcrush modules install <name>` installs from the marketplace, a local path or git. |
| **Chat / bot** | `not-started` | — | Slack, Discord, Matrix | Inbound (query state from chat) not built. Outbound alerts work today. |
| **Mobile** | `alpha` | `apps/mobile/` | App Store, Google Play (neither live) | Expo. `mobile-release.yml` builds a production Android AAB on EAS for every tag (`EXPO_TOKEN` is configured). iOS has never been built; nothing is submitted to a store. |
| **Wearable** | `not-started` | — | watchOS, Wear OS | Push-alert target only — owner + scope tbd. |
| **TV / console** | `not-started` | — | tvOS, Android TV | Unlikely fit; revisit if SOC dashboards become a customer ask. |
| **Voice** | `not-started` | — | Alexa Skills, Google Actions | "Hey Alexa, ask ThreatCrush for today's threat count" — post-API-stabilization. |
| **Embedded / IoT** | `not-started` | — | OpenWrt feed, buildroot | Ties to the hardware appliance roadmap in `docs/FUTURE_PLANS.md` (Q3+ 2026). |

---

## Distribution channels

Columns read: **which interfaces ship through this channel**.

| Channel | Status | Interfaces | Owner / path | Next action |
|---|---|---|---|---|
| **npm** | `shipping` | CLI (`@profullstack/threatcrush`) | `apps/cli/package.json`, `.github/workflows/npm-publish.yml` | Bump CLI to 0.1.0, publish. SDK: publish when marketplace ready. |
| **`curl \| sh`** | `shipping` | CLI | `apps/web/public/install.sh` | Smoke-test on fresh Ubuntu/macOS. |
| **Docker (GHCR)** | `preview` | Web | `Dockerfile`, `.github/workflows/docker-publish.yml` | Every tag pushes `ghcr.io/profullstack/threatcrush:{latest,<version>}`, but the package is private (anonymous pull: 401). Owner: make the package public. Docker Hub is skipped (no `DOCKER_USERNAME`). |
| **Railway** | `shipping` | Web | `railway.json` | Path was updated for monorepo; deploy once. |
| **GitHub Releases** | `preview` | Desktop | `.github/workflows/desktop-release.yml`, `apps/desktop/electron-builder.yml` | Green for v0.13.2–v0.13.7 on all four legs. Signing and notarization turn on once the `APPLE_*` / `WINDOWS_*` secrets exist (`docs/DESKTOP_RELEASE_TODO.md`); then this can be `shipping`. |
| **Homebrew** | `not-started` | CLI (tap), Desktop (cask) | `scripts/lib/package-managers/homebrew.ts` | First release: create `homebrew-threatcrush` tap repo. |
| **apt / deb** | `preview` | Desktop (via electron-builder) | `apps/desktop/electron-builder.yml` | `.deb` attached to each GitHub Release; no apt repository. For CLI: build a deb via `fpm` and host it; ppa later. |
| **rpm** | `not-started` | Desktop | electron-builder target | Add `rpm` to `linux.target`; test on fedora runner. |
| **AUR** | `not-started` | CLI | — | PKGBUILD after first stable release. |
| **Chocolatey** | `not-started` | CLI, Desktop | `scripts/lib/package-managers/` | Paired with Winget submission. |
| **Winget** | `not-started` | CLI, Desktop | `scripts/lib/package-managers/winget.ts` | After signed Windows artifact exists. `submit-packages.yml` has not run since 2026-08-08: releases are published with `GITHUB_TOKEN`, which does not trigger it; needs a `PKG_SUBMIT_TOKEN` PAT. |
| **Scoop** | `not-started` | CLI | `scripts/lib/package-managers/scoop.ts` | Lightweight; do after Winget. |
| **Snap** | `not-started` | Desktop | — | The AppImage works, so Snap is optional. |
| **Flatpak** | `not-started` | Desktop | — | Only if Linux distro asks. |
| **Nix** | `not-started` | CLI | — | Community interest → flake.nix. |
| **Chrome Web Store** | `not-started` | Extension | `apps/extension/` | Screenshots + privacy policy + review. |
| **Firefox AMO** | `not-started` | Extension | `apps/extension/` | Same build, separate review. |
| **Safari Web Extensions** | `not-started` | Extension | `apps/extension/` | Requires Apple Developer account. |
| **Apple App Store** | `not-started` | Mobile | `apps/mobile/` | No iOS build yet; needs Apple Developer Program + EAS iOS credentials. |
| **Google Play** | `not-started` | Mobile | `apps/mobile/`, `.github/workflows/mobile-release.yml` | Tag builds already produce the AAB; needs a Play Console account and an EAS submit key (`--auto-submit` on a production dispatch). |

---

## How this doc earns its keep

- One table per axis. No mixing interfaces with channels.
- Each row has a concrete next action so stale cells are visible.
- "Owner / path" points to where the work lives, not a name — names rot faster than paths.
- If a status hasn't changed in two releases, it's probably dead — consider dropping the row or moving it to `docs/FUTURE_PLANS.md`.

---

## Conventions for new surfaces

1. File lives under `apps/<surface>/` or (if smaller) as a module inside an existing app.
2. Own its own `package.json` with a scoped `@profullstack/` name — shows up in `pnpm -r list`.
3. Land in `shipping` only after: (a) smoke test covers it, (b) one distribution channel is green, (c) status cell here turned green in review.
4. If a surface needs a new channel, add the channel row *first*, with `not-started` — that's your reminder.
