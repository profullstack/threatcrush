# Make the ThreatCrush dashboard a real PWA (offline + push)

> ugig.net gig posting — implements [PRD-14](../14-pwa-offline-and-push.md)

- **Title:** Make the ThreatCrush dashboard a real PWA (offline + push)
- **Skills required:** `typescript`, `nextjs`, `pwa`, `service-workers`, `workbox`, `web-push`, `frontend`
- **Budget type:** fixed
- **Budget (USD):** 1,500 – 2,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/pwa-offline-push`
- **Spec:** `docs/prds/14-pwa-offline-and-push.md`

## What we need

The app is marketed as an installable PWA and ships a `manifest.json`, but there
is no service worker — so no offline shell, no cached views, no push. Make it a
real PWA on Next.js 16 (App Router, `output: standalone`).

## Scope

1. Register a service worker: precache the app shell; runtime stale-while-
   revalidate for overview/detections/findings reads. Validate `next-pwa`/Serwist
   vs hand-rolled against Next 16.
2. Meet installability criteria (Lighthouse PWA) on supported browsers; optional
   custom install prompt; audit/complete `manifest.json`.
3. Web Push (VAPID) opt-in subscription, delivered as a "critical alert"
   destination type integrated with PRD-08.
4. Cache invalidation on logout / org switch (no cross-org/user leakage).

## Acceptance criteria

- Lighthouse "Installable" passes; app opens offline showing last-cached data.
- Opt-in web push delivers a critical alert to an installed PWA.
- No stale data leaks across orgs/users after switch/logout. PR with green CI.
</content>
