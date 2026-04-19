# ThreatCrush Surfaces

Last updated: 2026-04-19

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
| **CLI** | `shipping` | `apps/cli/` | npm (`@profullstack/threatcrush`), `curl \| sh` | v0.1.16. `threatcrushd` daemon, IPC socket, systemd unit. |
| **TUI** | `shipping` | `apps/cli/src/tui/` | Bundled with CLI | react-blessed dashboard. `threatcrush tui`. |
| **API** | `shipping` | `apps/web/src/app/api/` | Same origin as web | REST, bearer-token auth. Used by CLI, desktop, extension. |
| **Webhooks (outbound)** | `shipping` | `apps/cli/src/daemon/alerts/` | Slack, generic webhook | Threat alerts emit when severity ≥ high. |
| **Email (outbound)** | `shipping` | `apps/cli/src/daemon/alerts/smtp.ts` | SMTP via `nodemailer` | Configure `[alerts.email]` in `threatcrushd.conf`. |
| **Desktop** | `preview` | `apps/desktop/` | GitHub Releases (unsigned) | Electron. IPC bridge to local `threatcrushd` via Unix socket. macOS/Windows CI still untested. |
| **Browser extension** | `preview` | `apps/extension/` | Sideload from source | Vite + React 19 + MV3. Store submissions post-v0.1.0. |
| **SDK** | `alpha` | `apps/sdk/` | npm (`@threatcrush/sdk`) — not yet published | Types for module authors. Publish ties to marketplace readiness. |
| **Plugin / integration** | `alpha` | `apps/cli/src/daemon/module-host.ts` | Module marketplace API | `threatcrush modules install` does local + git; full marketplace v0.2. |
| **Chat / bot** | `not-started` | — | Slack, Discord, Matrix | Inbound (query state from chat) not built. Outbound alerts work today. |
| **Mobile** | `deferred` | `apps/mobile/` | App Store, Google Play | Expo scaffolded. `EXPO_TOKEN`/EAS not configured. Roadmap Q3 2026. |
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
| **Docker (Hub + GHCR)** | `shipping` | Web | `Dockerfile`, `.github/workflows/docker-publish.yml` | Re-verify after monorepo move. |
| **Railway** | `shipping` | Web | `railway.json` | Path was updated for monorepo; deploy once. |
| **GitHub Releases** | `preview` | Desktop | `.github/workflows/desktop-release.yml`, `apps/desktop/electron-builder.yml` | Test full matrix on real mac/win runners. |
| **Homebrew** | `not-started` | CLI (tap), Desktop (cask) | `scripts/lib/package-managers/homebrew.ts` | First release: create `homebrew-threatcrush` tap repo. |
| **apt / deb** | `preview` | Desktop (via electron-builder) | `apps/desktop/electron-builder.yml` | For CLI: build a deb via `fpm` and host it; ppa later. |
| **rpm** | `not-started` | Desktop | electron-builder target | Add `rpm` to `linux.target`; test on fedora runner. |
| **AUR** | `not-started` | CLI | — | PKGBUILD after first stable release. |
| **Chocolatey** | `not-started` | CLI, Desktop | `scripts/lib/package-managers/` | Paired with Winget submission. |
| **Winget** | `not-started` | CLI, Desktop | `scripts/lib/package-managers/winget.ts` | After signed Windows artifact exists. |
| **Scoop** | `not-started` | CLI | `scripts/lib/package-managers/scoop.ts` | Lightweight; do after Winget. |
| **Snap** | `not-started` | Desktop | — | Confluent AppImage works — Snap is optional. |
| **Flatpak** | `not-started` | Desktop | — | Only if Linux distro asks. |
| **Nix** | `not-started` | CLI | — | Community interest → flake.nix. |
| **Chrome Web Store** | `not-started` | Extension | `apps/extension/` | Screenshots + privacy policy + review. |
| **Firefox AMO** | `not-started` | Extension | `apps/extension/` | Same build, separate review. |
| **Safari Web Extensions** | `not-started` | Extension | `apps/extension/` | Requires Apple Developer account. |
| **Apple App Store** | `deferred` | Mobile | `apps/mobile/` | Blocked on mobile product. |
| **Google Play** | `deferred` | Mobile | `apps/mobile/` | Blocked on mobile product. |

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
