# ThreatCrush Module — Paid / Auth-Gated Boilerplate

A starter for **paid** ThreatCrush modules that authenticate against an
upstream API. Ships with three CLI helpers — `login`, `logout`, `status` —
and a license-gated `init()` that refuses to poll without a valid key.

Use this when your module needs to:

- gate functionality behind a paid license
- call an upstream API with `Authorization: Bearer <license_key>`
- let the operator activate / deactivate / inspect the license from the shell

## What's included

- `mod.toml` — manifest + `pricing.type = "paid"` + `price_usd`
- `package.json` — declares three `bin/` entries
- `src/index.ts` — `PaidFeedExampleModule` with license-gated init + tick loop
- `src/auth.ts` — license file persistence (`~/.config/threatcrush/<module>/license.json`) and a `validateWithBackend()` stub to replace
- `bin/login.ts` — prompts for / accepts a license key, validates, persists
- `bin/logout.ts` — deletes the saved license
- `bin/status.ts` — shows the saved license and re-validates it
- `config/example.conf.toml`
- `tsconfig.json`, `.gitignore`

## Clone it

```bash
cp -R boilerplates/paid-module ~/src/my-paid-module
cd ~/src/my-paid-module
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

## Activate locally

```bash
# during development
pnpm login --key=test-key-xxxxxxxx
pnpm status
pnpm logout

# after publishing
npx paid-feed-example-login --key=...
npx paid-feed-example-status
npx paid-feed-example-logout
```

The license is stored at `~/.config/threatcrush/<module-name>/license.json`
with mode `0600`. The module's `init()` reads it on load.

## Wire up your real backend

The included `validateWithBackend()` in `src/auth.ts` is a stub. Replace its
body with a real call to your billing/license API — there's a commented
example showing the typical `POST /v1/license/verify` shape.

Likewise, `fetchPaidFeed()` in `src/index.ts` is a placeholder hitting
`${api_base}/v1/feed/recent` with the license as a bearer token. Swap for
your actual endpoint and parse the response into `ThreatEvent`s.

## Rename it

- `mod.toml` → `name`, `description`, `author`, `homepage`, `pricing`
- `package.json` → `name`, `bin` keys (e.g. `mymod-login`, `mymod-logout`,
  `mymod-status`)
- `src/auth.ts` → `MODULE_NAME` constant
- `src/index.ts` → class name and `name` field

## Publishing checklist

- bump `mod.toml` `version`
- set `pricing.type = "paid"` and a real `price_usd` / `billing` cadence
- make sure `author` matches your ThreatCrush account email
- sign in at `https://threatcrush.com`
- publish from `https://threatcrush.com/store/publish`

## See also

- `boilerplates/module-example/` — minimal hello-world (event subscribe only)
- `boilerplates/free-module/` — free / MIT API-integration template (no auth)
