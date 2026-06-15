# PRD — Dashboard detections feed

- **Status:** Draft · Not started
- **Surface(s):** Web/PWA (`apps/web/src/app/org/[slug]`)
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §5 "Dashboard" → Detections view · [[00-detection-data-model]] · [[08-alerting-and-alert-rules]]

## Problem

The dashboard today shows **servers** and **properties** only
(`apps/web/src/app/org/[slug]/{servers,properties}`). The PRD's core "Detections"
view — the real-time feed of what's attacking the fleet — does not exist. This is
the primary value screen of a security dashboard and is currently absent.

## Goals

1. A detections feed (per-server and fleet-wide) reading from `detections` ([[00-detection-data-model]]).
2. Filters: severity, rule, hostname, timeframe (PRD §5.3).
3. Near-real-time updates via Supabase Realtime (optional fallback to polling).
4. Detection detail with metadata, source IP, linked remediation.

## Non-goals

- Long-range analytics/charts beyond basic counts (later).
- Cross-org views.

## Current state

- `org/[slug]/page.tsx` overview + `servers/` + `properties/` exist.
- No detections view, no realtime wiring (no `serviceWorker`/realtime refs found in web).

## Requirements

1. **Fleet detections page** at `org/[slug]/detections` with filter bar.
2. **Server detections** tab on `servers/[id]`.
3. **Realtime**: subscribe to `detections` inserts (Supabase Realtime); graceful polling fallback.
4. **Detail**: severity, rule_id (link to rule), source_ip, username, detected_at, status; link to any `remediation_action`.
5. **Overview tie-in**: "recent threats" + "servers needing attention" on `org/[slug]` overview (PRD §5.1).
6. PWA-friendly (responsive; works in installed app — see [[14-pwa-offline-and-push]]).

## API

- `GET /api/orgs/[id]/detections` (+ server-scoped) with filter query params and pagination.

## Acceptance criteria

- [ ] Detections list renders with working severity/rule/host/timeframe filters.
- [ ] New detection appears without manual refresh (realtime or ≤polling interval).
- [ ] Overview shows recent-threats + needs-attention counts.
- [ ] Mobile/installed layout is usable.

## Out of scope / later

- Saved filter views, export.

## Open questions

- Realtime at launch or polling-first? (Recommend polling-first if Realtime not already enabled, realtime fast-follow.)
</content>
