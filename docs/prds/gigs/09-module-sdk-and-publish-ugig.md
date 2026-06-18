# Build & publish the ThreatCrush module SDK (`@threatcrush/sdk`)

> ugig.net gig posting — implements [PRD-09](../09-module-sdk-and-publish.md)

- **Title:** Build & publish the ThreatCrush module SDK (`@threatcrush/sdk`)
- **Skills required:** `typescript`, `nodejs`, `sdk-design`, `npm-publishing`, `json-schema`, `docs`
- **Budget type:** fixed
- **Budget (USD):** 1,500 – 2,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/module-sdk`
- **Spec:** `docs/prds/09-module-sdk-and-publish.md`

## What we need

`@threatcrush/sdk` is 146 lines of types, marked alpha, and unpublished —
blocking community module authoring. Define and freeze the public module
contract, publish it, and document authoring.

## Scope

1. Manifest spec (name, version, kind, entrypoint, config schema, compatibility,
   declared capabilities) and typed lifecycle hooks (init/start/stop, event
   subscription, detection emit, remediation request).
2. Re-export the shared detection/rule/alert/ingest schemas (PRD-00, PRD-01) so
   authors and the platform share one source of truth — imported by web API + CLI.
3. Publish `@threatcrush/sdk` to npm (public) with semver + changelog, wired into
   CI.
4. Authoring guide + an `examples/` starter module.

## Acceptance criteria

- `npm i @threatcrush/sdk` works; types resolve.
- A starter module built only against the published SDK loads in `module-host`.
- Web API and CLI both import the shared schemas from the SDK (no duplication).
- PR with green CI and published docs.
