# ThreatCrush monorepo

This repo ships every ThreatCrush surface from one tree. pnpm workspaces.
Node ≥ 22.

```
.
├── apps/
│   ├── web/          Next.js 16 — threatcrush.com (PWA, API, org pages)
│   ├── cli/          @profullstack/threatcrush — CLI + threatcrushd daemon + TUI
│   ├── desktop/      @profullstack/threatcrush-desktop — Electron + react-blessed
│   ├── mobile/       Expo (deferred for v0.1.0)
│   ├── extension/    Vite + React MV3 extension (dev preview)
│   └── sdk/          @threatcrush/sdk — types for module authors
├── supabase/         Migrations + seed SQL
├── scripts/          release, version-bump, submit-packages, smoke-test
├── docs/             SURFACES.md, PRE_LAUNCH.md, FUTURE_PLANS.md, etc.
├── boilerplates/     Starter module template
├── Dockerfile        Builds apps/web as standalone for Railway
└── railway.json      Deploy config
```

## Common commands

From the repo root:

```bash
pnpm install               # hydrate all workspaces
pnpm dev                   # run apps/web in dev mode
pnpm build                 # build apps/web
pnpm build:cli             # build apps/cli (CLI + daemon bundles)
pnpm build:desktop         # build apps/desktop
pnpm build:all             # build every app (recursive)
pnpm test                  # run every app's test script
pnpm version:patch|:minor  # bump all package.json versions in lockstep
pnpm --filter <pkg> <cmd>  # target one workspace
```

Per-app dev loops live in each `apps/<name>/README.md`.

## Where things live

- **Web API** — `apps/web/src/app/api/**`
- **Daemon** — `apps/cli/src/daemon/` (boot, IPC, alerts, module host, runs worker)
- **CLI commands** — `apps/cli/src/commands/*.ts`
- **TUI** — `apps/cli/src/tui/app.tsx` (react-blessed)
- **Desktop ↔ daemon IPC** — `apps/desktop/src/main/daemon-client.ts`
- **Shared CLI config** — `apps/cli/src/core/cli-config.ts` (bearer token lives at `~/.threatcrush/config.json`)
- **Runtime paths** — `apps/cli/src/daemon/paths.ts` picks `/etc/threatcrush` when root, `~/.threatcrush` otherwise

## Environment

- `.env` at the repo root is symlinked into `apps/web/.env` so Next.js picks it up during `pnpm dev`.
- The daemon reads `/etc/threatcrush/threatcrushd.conf` (or `~/.threatcrush/threatcrushd.conf`) for alert channels + modules.
- `SENTRY_DSN` and `NEXT_PUBLIC_SENTRY_DSN` are optional. Unset → no-op.

## Release flow

1. `pnpm version:minor` — bumps every `package.json` and tags `v<version>`
2. `git push --follow-tags`
3. GitHub workflows kick in:
   - `npm-publish.yml` publishes `apps/cli` to npm
   - `desktop-release.yml` builds + uploads Electron artifacts
   - `docker-publish.yml` pushes the web image to GHCR + Docker Hub
4. `railway up` (or push to the tracked branch) deploys `apps/web`

See `docs/SURFACES.md` for the status of every interface + distribution channel.

## Adding a new surface

1. `mkdir -p apps/<name>` with its own `package.json` — must be scoped `@profullstack/…` or `@threatcrush/…`
2. Add to `SURFACES.md` with `not-started` before writing code — the row is your reminder
3. Add a `README.md` with the dev loop so contributors don't have to guess

## Known sharp edges

- `apps/cli/` installs via the root workspace install — native deps (`better-sqlite3`) rebuild automatically
- Next.js standalone output in `apps/web/.next/standalone/apps/web/` — the `Dockerfile` copies `public/` and `.next/static` into it because Next.js standalone doesn't include static assets
- Electron packaging requires `npmRebuild: false` because pnpm's symlink layout confuses `@electron/rebuild` (there are no native deps in the desktop app anyway)
