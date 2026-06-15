# Build the ThreatCrush dashboard detections feed

> ugig.net gig posting — implements [PRD-10](../10-dashboard-detections-feed.md)

- **Title:** Build the ThreatCrush dashboard detections feed
- **Skills required:** `typescript`, `react`, `nextjs`, `tailwind`, `supabase`, `supabase-realtime`, `frontend`
- **Budget type:** fixed
- **Budget (USD):** 1,800 – 3,000
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/dashboard-detections`
- **Spec:** `docs/prds/10-dashboard-detections-feed.md`

## What we need

The primary value screen of a security dashboard — the real-time feed of what's
attacking the fleet — doesn't exist (the dashboard has only servers + properties).
Build the detections feed reading from `detections` (PRD-00).

## Scope

1. Fleet detections page at `org/[slug]/detections` with a filter bar (severity,
   rule, hostname, timeframe) + pagination; a detections tab on `servers/[id]`.
2. Near-real-time updates via Supabase Realtime with a graceful polling fallback.
3. Detection detail: severity, rule_id (linked), source_ip, username, status,
   linked remediation action.
4. Overview tie-in: "recent threats" + "servers needing attention" on the org
   overview. `GET /api/orgs/[id]/detections` with filter params.

## Acceptance criteria

- List renders with working severity/rule/host/timeframe filters.
- A new detection appears without manual refresh (realtime or ≤ poll interval).
- Usable on mobile / installed-PWA layout. PR with green CI.
</content>
