# ThreatCrush Module Example

A minimal starter module publishers can clone and modify.

## What this includes

- `mod.toml` — module manifest / marketplace metadata
- `src/index.ts` — example module implementation using the planned `@threatcrush/sdk` interface
- `config/example.conf.toml` — example drop-in config
- `package.json` / `tsconfig.json` — simple TypeScript scaffold
- `.gitignore`

## Clone this boilerplate

```bash
git clone https://github.com/profullstack/threatcrush.git
cd threatcrush
cp -R boilerplates/module-example ~/src/my-threatcrush-module
cd ~/src/my-threatcrush-module
```

Or just copy the folder into a new repo.

## Rename it

Update these fields first:

- `mod.toml`
  - `name`
  - `version`
  - `description`
  - `author`
  - `homepage`
  - pricing block
- `package.json`
  - `name`
  - `description`
- `src/index.ts`
  - class name
  - event logic

## Local development

```bash
pnpm install
pnpm build
```

## Suggested structure

```text
module-example/
  mod.toml
  package.json
  tsconfig.json
  src/
    index.ts
  config/
    example.conf.toml
```

## Publishing checklist

- pick a unique module name
- add a real logo / docs / homepage if you have them
- make sure version is semver
- set pricing to `free`, `freemium`, or `paid`
- make sure author email matches your ThreatCrush account email
- sign in at `https://threatcrush.com`
- publish from `https://threatcrush.com/store/publish`

## Notes

This follows the current ThreatCrush PRD shape, so treat it as the canonical starter until the module SDK is finalized.
