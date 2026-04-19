# ThreatCrush TODO

Last updated: 2026-04-19

Repo is now a monorepo under `apps/` — `web`, `cli`, `desktop`, `mobile`, `extension`, `sdk`.

---

## 🔴 Remaining v0.1.0 blockers

Everything here must be done before we tag `v0.1.0` and publish.

### 1. Ops — wire real env vars in production
The code now throws loudly when these are missing (see `apps/web/src/lib/supabase.ts`),
so prod deploys will fail fast rather than silently use placeholders.

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `COINPAYPORTAL_API_KEY`, `COINPAYPORTAL_BUSINESS_ID`, `COINPAYPORTAL_WEBHOOK_SECRET`
- `TELNYX_API_KEY`, `TELNYX_PHONE_NUMBER`
- Supabase Dashboard → Auth → SMS webhook URL = `https://threatcrush.com/api/hooks/send-sms`

### 2. Desktop release pipeline — test matrix jobs on real runners
`.github/workflows/desktop-release.yml` was fixed (artifact paths, drop linux-arm64) and
`apps/desktop/electron-builder.yml` is now correct (Linux build verified locally).
The macOS + Windows jobs are untested. Before launch:
- [ ] Trigger `workflow_dispatch` on a pre-release tag, confirm all three platforms pass
- [ ] If signing secrets are present (`APPLE_CERTIFICATE`, `WINDOWS_CERTIFICATE`, …),
      make sure the signed artifacts are actually signed

### 3. Smoke test on a clean VM
`scripts/smoke-test.sh` runs locally; run it once against a **fresh** Ubuntu VM to
exercise the `curl | sh` → `init` → `login` → `properties run` path.
- [ ] `curl -fsSL https://threatcrush.com/install.sh | sh` succeeds on bare `ubuntu:24.04`
- [ ] `TC_EMAIL=... TC_PASSWORD=... scripts/smoke-test.sh` completes 11/11 steps

### 4. Version + publish
- [ ] Bump `0.1.16` → `0.1.0` (or mint `0.2.0` — team call)
- [ ] `pnpm run version:patch` / `:minor`
- [ ] `git tag v0.1.0 && git push --tags`
- [ ] `pnpm --filter @profullstack/threatcrush publish --access public`
- [ ] Docker Hub / GHCR push via `docker-publish.yml`
- [ ] Verify `install.sh` points at the newly published npm version

### 5. Post-launch watch
- [ ] Sentry / error-reporting wired into `apps/web` and `threatcrushd`
- [ ] Basic health endpoint smoke check on Railway

---

## 🟡 Scope-cut for v0.1.0 (defer to v0.2 / later)

### Module marketplace
- `threatcrush modules install` now does real local + git clones, removal works,
  manifests are validated. Server-side catalog (search, list, install tracking)
  is still read-only. Full marketplace w/ payments → v0.2.

### Mobile app
- Sanity screen in `apps/mobile/app/index.tsx`; demo data in `apps/mobile/src/stores/events.ts`
- `EXPO_TOKEN` not set, EAS project not linked
- App Store / Play Console not set up
- Launch messaging on the homepage already says "In development" with a beta-waitlist link

### Browser extension
- Code in `apps/extension/` works; submission review for Chrome / Firefox / Safari not started
- Homepage card says "Dev preview · Sideload from source →" which is honest

### `@threatcrush/sdk` npm publish
- `apps/sdk/` has the types; no published package yet
- Community module authoring story waits on this

### Homebrew / Winget / Scoop submissions
- Scripts exist in `scripts/lib/package-managers/` but haven't been exercised
- Punt to the next release cycle

---

## 🟢 Done during the v0.1.0 run-up (for posterity)

### CLI + daemon
- [x] `threatcrushd` real daemon (Unix-socket IPC, PID file, systemd unit)
- [x] Built-in modules: `log-watcher`, `ssh-guard` (auto-discovered, handle `EACCES`)
- [x] `threatcrush start | stop | status | daemon | logs`
- [x] `threatcrush install-service` / `uninstall-service` drops a systemd unit
- [x] `threatcrush monitor`, `scan`, `pentest`, `init`
- [x] `threatcrush login | logout | whoami` against `/api/auth/login`
- [x] `threatcrush orgs`, `servers`, `connect` (SSH)
- [x] `threatcrush properties add | list | remove | run | runs | import`
- [x] `threatcrush modules list | install | remove` — real local/git installs + manifest validation
- [x] `threatcrush help [cmd]` subcommand
- [x] react-blessed TUI dashboard subscribes to the daemon IPC

### Scheduled & queued runs
- [x] `property_runs` table + `claim_next_property_run` RPC
- [x] `properties.schedule` + `next_run_at` columns
- [x] Daemon `RunsWorker` polls `/runs/pending` every 30 s
- [x] Daemon hits `/schedules/tick` every 2 min to enqueue overdue runs
- [x] Property detail page shows run history, expandable findings, CSV export
- [x] Schedule selector on the new-property form + detail page

### Web
- [x] Full auth flow (email/password, phone OTP via Telnyx)
- [x] `/org/[slug]` dashboards for servers + properties + detail pages
- [x] Supabase env-var guards (throw loudly, no placeholder fallbacks)
- [x] Waitlist + CoinPay + Stripe integration (graceful degradation copy)
- [x] Homepage "Coming soon" → honest status pills w/ action links

### Desktop
- [x] Main-process IPC client connects to `threatcrushd` Unix socket
- [x] Preload exposes `daemonRequest` / `onEvent` to the renderer
- [x] `electron-builder.yml` produces AppImage + .deb locally (mac / win untested)

### Monorepo
- [x] `apps/{cli,desktop,mobile,extension,sdk,web}` layout
- [x] `pnpm-workspace.yaml` pointed at `apps/*`
- [x] `Dockerfile` + `railway.json` + workflows + version-bump scripts updated

### DX
- [x] `scripts/smoke-test.sh` — 11-step v0.1.0 launch validation, green locally
- [x] This document refreshed
