# PRD — Module SDK & npm publish

- **Status:** Draft · Not started
- **Surface(s):** SDK (`apps/sdk`), CLI (`module-host`)
- **Priority:** P1
- **Owner:** TBD
- **Related:** `docs/PRD.md` §"packages/sdk" · `docs/SURFACES.md` (SDK `alpha`, unpublished) · [[01-detection-rule-engine]] · [[16-module-marketplace]]

## Problem

`@threatcrush/sdk` is 146 lines of types in `apps/sdk/src/index.ts`, marked
`alpha`, and **not published to npm**. Community module authoring — a core part of
the product story and the marketplace — is blocked on it. The CLI's
`module-host.ts` loads modules, but third parties have no documented, typed
contract to build against.

## Goals

1. Define and freeze the public module contract: manifest, lifecycle hooks, event/detection types, config schema.
2. Re-export the shared detection-rule + ingest schemas ([[00-detection-data-model]], [[01-detection-rule-engine]]) so authors and the platform share one source of truth.
3. Publish `@threatcrush/sdk` to npm with semver + changelog.
4. Author docs + a starter module template.

## Non-goals

- Marketplace payments/publishing flow ([[16-module-marketplace]]).
- A plugin permission sandbox beyond manifest validation (later hardening).

## Current state

- `apps/sdk/src/index.ts` — 146 lines of types; `dist/` built but unpublished.
- `apps/cli/src/daemon/module-host.ts` loads local/git modules; manifests validated (per `docs/TODO.md`).

## Requirements

1. **Manifest spec**: name, version, kind, entrypoint, config schema, compatibility metadata, capabilities/permissions declared.
2. **Lifecycle**: `init/start/stop`, event subscription, detection emit, remediation request — typed.
3. **Shared schemas**: detection payload, rule schema, alert payload exported here and imported by web API + CLI.
4. **Publish**: `@threatcrush/sdk` to npm (public), wired into `npm-publish.yml` or its own job.
5. **Docs**: authoring guide + `examples/` starter module.

## Acceptance criteria

- [ ] `npm i @threatcrush/sdk` works; types resolve.
- [ ] A starter module built only against the published SDK loads in `module-host`.
- [ ] Web API and CLI both import the shared schemas from the SDK (no duplicate definitions).
- [ ] Authoring docs published.

## Out of scope / later

- Module sandboxing / capability enforcement at runtime.
- Paid module distribution.

## Open questions

- Does publishing the SDK gate on marketplace readiness, or ship standalone first? (Recommend standalone; marketplace can follow.)
