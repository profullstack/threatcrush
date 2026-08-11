# `@threatcrush/scan`

The scan rules and engine, shared by the CLI, web, desktop and extension.

Previously this lived at `apps/cli/src/scan/`, which meant the CLI was the only
surface that could run a scan. Every other app either did without or would have
grown its own copy of the rules.

## Two entry points

```ts
import { scanText, CODE_RULES } from '@threatcrush/scan';        // anywhere
import { scanPath, buildSarif } from '@threatcrush/scan/node';   // needs a filesystem
```

| entry | contains | runs in |
|---|---|---|
| `.` | rules, `scanText`, language detection, suppressions, severity | browser, worker, Node |
| `./node` | `scanPath` tree walker, dependency scan, SARIF output | Node only |

The default entry point imports nothing from `node:`. That is enforced by
`src/__tests__/boundaries.test.ts`, not by convention — a browser bundle breaks
at the *consumer's* build if a filesystem import creeps in, which is a failure
that surfaces late and in the wrong repository.

Verify by hand at any time:

```sh
npx esbuild src/index.ts --bundle --platform=browser --format=esm --outfile=/dev/null   # succeeds
npx esbuild src/node/index.ts --bundle --platform=browser --format=esm --outfile=/dev/null  # fails, by design
```

## Why `exports` points at TypeScript source

This is an internal package: `exports` resolves to `src/*.ts` rather than a
build output.

The alternative — compiling to `dist/` — introduces a build ordering
requirement, and the release workflow runs `pnpm --filter @profullstack/threatcrush build`
alone. A package that had to be built first would publish a broken CLI the
first time someone forgot, and the failure would be a runtime `MODULE_NOT_FOUND`
in the published artefact rather than a red build.

Consumers therefore transpile it themselves:

- **CLI** — bundled by tsup via `noExternal`, so the published package stays
  self-contained and gains no dependency on an unpublished package.
- **Next.js** (web) — add `transpilePackages: ['@threatcrush/scan']`.
- **Vite** (desktop, extension) — works as-is; Vite transpiles linked workspace
  sources by default.

If this package is ever published standalone, add a build step and switch
`exports` to `dist` with a `publishConfig` override. Nothing else needs to move.

## Adding a rule

Rules live in `src/code-rules.ts`, credentials in `src/secret-rules.ts`,
manifests in `src/manifest-rules.ts`. Two invariants are enforced by tests:

- **Every language the scanner claims must have at least one rule.** `shell`
  and `php` were both listed as supported while no rule targeted them, so those
  files were read and reported clean whatever they contained.
- **Every rule is tested against the corrected shape as well as the vulnerable
  one.** A rule that only fires on bad code is untested against the good code
  standing next to it, which is where false positives come from.
