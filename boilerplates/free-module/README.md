# ThreatCrush Module — Free / MIT Boilerplate

A working starter that polls the **URLhaus public feed** (no API key required)
and emits one `ThreatEvent` per newly-seen malicious URL.

Use this as the canonical pattern for any **free / open-source** module that
pulls data from an external HTTP API and feeds it into the ThreatCrush event
bus.

## Why this template

- Real fetch loop with state persistence (`ctx.getState` / `ctx.setState`)
- CSV parsing example you can swap for JSON / NDJSON
- Severity classification stub
- MIT-licensed — copy, fork, ship

## What's included

- `mod.toml` — manifest + marketplace metadata, pricing = `free`
- `package.json` / `tsconfig.json` — TypeScript scaffold
- `src/index.ts` — `UrlhausFeedModule implements ThreatCrushModule`
- `config/example.conf.toml` — drop-in config override
- `LICENSE` — MIT
- `.gitignore`

## Clone it

```bash
cp -R boilerplates/free-module ~/src/my-threatcrush-module
cd ~/src/my-threatcrush-module
pnpm install
pnpm build
```

> **Heads up:** `@threatcrush/sdk` is not yet on npm. Until it is, install it
> from the ThreatCrush monorepo, e.g.:
>
> ```bash
> pnpm add ../../path/to/threatcrush/apps/sdk
> ```
>
> Once published you can drop the override and `pnpm install` will resolve
> normally.

## Rename it

Update the obvious fields:

- `mod.toml` → `name`, `description`, `author`, `homepage`
- `package.json` → `name`, `description`
- `src/index.ts` → class name, `name` field, parser, classifier
- `LICENSE` → fill in `<year>` and `<your name>`

## How it works

1. `init(ctx)` — stash the context.
2. `start()` — kicks off `tick()` immediately, then on `poll_interval_seconds`.
3. `tick()` — fetches the upstream feed, filters anything `<= last_seen_id`,
   and emits a `ThreatEvent` per fresh entry above the configured severity
   threshold. The newest id is persisted so restarts don't re-emit.
4. `stop()` — clears the interval.

## Swap the upstream

Replace `fetchFeed()` and `parseUrlhausCsv()` with your own. The shape that
matters is: produce `ThreatEvent`s and call `ctx.emit(event)`.

## Publishing checklist

- pick a unique module name in `mod.toml`
- bump `version` to a real semver
- set `pricing.type = "free"` (this template defaults to that)
- make sure `author` matches your ThreatCrush account email
- sign in at `https://threatcrush.com`
- publish from `https://threatcrush.com/store/publish`

## See also

- `boilerplates/module-example/` — minimal hello-world module (event subscribe only)
- `boilerplates/paid-module/` — paid module with `login` / `logout` / `status`
  CLI commands and a license-gated init
