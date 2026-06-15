# Build the ThreatCrush module marketplace (catalog + publish + payments)

> ugig.net gig posting — implements [PRD-16](../16-module-marketplace.md)

- **Title:** Build the ThreatCrush module marketplace (catalog + publish + payments)
- **Skills required:** `typescript`, `nextjs`, `react`, `supabase`, `payments`, `stripe`, `coinpay`, `fullstack`
- **Budget type:** fixed
- **Budget (USD):** 2,500 – 4,000
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/module-marketplace`
- **Spec:** `docs/prds/16-module-marketplace.md`

## What we need

The README heavily features `threatcrush store`, and the web has store/publish
pages, but the catalog is read-only with no payments — so community module
monetization isn't real. (Scoped as v0.2 / post-launch.) Build the full
marketplace.

## Scope

1. Server-side catalog: search + list with filters; version resolution; install
   tracking counters.
2. Publish flow: validated submission tied to the SDK manifest (PRD-09) with
   ownership/auth.
3. Reviews/ratings surfaced in the store UI (tables already exist).
4. Paid modules via the existing CoinPay/Stripe integration; entitlement check on
   install. CLI parity: `store search/publish/install` against the live catalog.

## Acceptance criteria

- Search returns ranked results from the server catalog; an author can publish a
  validated module that then appears in search.
- A paid module requires purchase before install; entitlement enforced.
- Install counts + reviews render in the store UI. PR with green CI.
</content>
