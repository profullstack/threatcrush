# PRD — Module marketplace

- **Status:** Draft · Not started
- **Surface(s):** Web (`apps/web/src/app/store`, `/api/modules`), CLI (`store` command)
- **Priority:** P2 (post-launch / v0.2)
- **Owner:** TBD
- **Related:** `docs/PRD.md` Phase 4 "detection marketplace" · `docs/TODO.md` ("Full marketplace w/ payments → v0.2") · [[09-module-sdk-and-publish]]

## Problem

The README heavily features `threatcrush store` (search/publish) and the web has
`store/` + `store/publish/` pages and a `/api/modules` surface, but per
`docs/TODO.md` the server-side catalog is **read-only** — search/list/install
tracking is partial and there are no payments. Community module monetization (a
stated revenue stream) is not yet real. Captured here so v0.2 scope is explicit;
**not a launch blocker** for the core web/CLI product.

## Goals

1. Server-side catalog: search, list, version resolution, install tracking.
2. Publish flow: author submits a module (validated against the SDK manifest).
3. Reviews/ratings (tables already exist in the modules marketplace migration).
4. Paid modules via CoinPayPortal/Stripe (free + paid tiers).

## Non-goals (this PRD)

- Runtime module sandboxing (separate security hardening effort).
- Curated central detection-rule feed (overlaps [[01-detection-rule-engine]]).

## Current state

- `apps/web/src/app/store/` + `store/publish/` pages; `/api/modules`, `/api/modules/[slug]/{install,review}`, `/api/modules/installed`, `/api/modules/fetch-meta`.
- `supabase/migrations/20260404140000_modules_marketplace.sql` — modules/versions/installs/reviews tables.
- CLI `modules install` does real local + git installs; full catalog/payments deferred.

## Requirements

1. **Catalog API**: search + list with filters; install tracking counters.
2. **Publish**: validated submission tied to SDK manifest ([[09-module-sdk-and-publish]]); ownership/auth.
3. **Reviews/ratings** surfaced in store UI.
4. **Payments**: paid module purchase via existing CoinPay/Stripe integration; entitlement check on install.
5. **CLI parity**: `store search/publish/install` against the live catalog.

## Acceptance criteria

- [ ] Search returns ranked results from the server catalog.
- [ ] An author can publish a validated module; it appears in search.
- [ ] A paid module requires purchase before install; entitlement enforced.
- [ ] Install counts + reviews render in store UI.

## Out of scope / later

- Module sandbox/permissions enforcement.
- Revenue share / payouts dashboard.

## Open questions

- Is any marketplace surface launch-blocking, or fully v0.2? (Default: v0.2 per `docs/TODO.md`.)
