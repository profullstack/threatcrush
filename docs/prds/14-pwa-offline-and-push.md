# PRD — PWA offline & push

- **Status:** Draft · Not started
- **Surface(s):** PWA (`apps/web`)
- **Priority:** P1
- **Owner:** TBD
- **Related:** `docs/PRD.md` §6 "PWA dashboard" · `docs/SURFACES.md` (PWA/Web `shipping`)

## Problem

The web app is described as an **installable PWA** ("installable mobile/desktop-like
dashboard access"), and a `manifest.json` exists at `apps/web/public/manifest.json`.
But there is **no service worker** (no `serviceWorker`/`workbox`/`next-pwa`
references in the web source), so the app is not truly installable-with-offline,
has no cached views, and cannot receive push notifications. The PRD calls for
installability, offline-friendly cached views, and richer notifications.

## Goals

1. Register a service worker (offline shell + cached last-known fleet/detection views).
2. Pass installability criteria (Lighthouse PWA) on supported browsers.
3. Web Push for critical alerts (opt-in), integrated with [[08-alerting-and-alert-rules]].
4. Verify `manifest.json` completeness (icons, theme, display, start_url).

## Non-goals

- Full offline write/sync (read-mostly cached views at launch).
- Native mobile push (that's the deferred mobile app).

## Current state

- `apps/web/public/manifest.json` + `public/icons/manifest.json` present.
- No service worker / offline strategy / push subscription.

## Requirements

1. **Service worker**: precache app shell; runtime-cache read API responses (stale-while-revalidate) for overview/detections/findings.
2. **Install**: meet installability criteria; optional custom install prompt.
3. **Web Push**: subscription flow + VAPID keys; deliver critical alerts as a push destination type ([[08-alerting-and-alert-rules]]).
4. **Manifest audit**: complete icons set, theme/background color, display=standalone, start_url, scope.
5. Cache invalidation on logout / org switch.

## Acceptance criteria

- [ ] Lighthouse "Installable" passes.
- [ ] App opens offline showing last-cached fleet/detection data.
- [ ] Opt-in web push delivers a critical alert to an installed PWA.
- [ ] No stale data leaks across orgs/users after switch/logout.

## Out of scope / later

- Background sync of operator actions made while offline.

## Open questions

- `next-pwa`/Serwist vs hand-rolled SW with Next 16 App Router + `output: standalone`? Validate compatibility.
</content>
