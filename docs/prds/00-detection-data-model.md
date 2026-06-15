# PRD — Detection data model & event ingest

- **Status:** Draft · Not started
- **Surface(s):** API/DB (Supabase + `apps/web/src/app/api`, `apps/cli/src/daemon`)
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §"Proposed data model", §"API concepts" · [[01-detection-rule-engine]] · [[08-alerting-and-alert-rules]] · [[10-dashboard-detections-feed]]

## Problem

The master PRD describes a detections + remediation + hardening platform, but the
shipped schema has **none of the supporting tables**. Migrations under
`supabase/migrations/` cover `waitlist`, `referrals`, modules marketplace, `users`,
`organizations_and_servers`, `properties`, and `property_runs` — but there is no
`detections`, `remediation_actions`, `hardening_findings`, `alert_destinations`,
`alert_rules`, `allowlists`, or `rule_registry`. There is a `POST /api/events`
route and per-server `events` route, but no canonical normalized detection store
the dashboard and alerting can read from.

Without this backbone, the daemon has nowhere to durably report what it detected
or remediated, and the dashboard PRDs (10–13) have no data source. This is the
foundation every other CLI/web detection feature depends on.

## Goals

1. Land the detection/remediation/hardening/alerting/allowlist data model in Supabase.
2. Provide a single authenticated, normalized ingest path the daemon uses.
3. Keep ingest **normalized detections only** by default (privacy: no raw logs), per PRD §10.
4. RLS-scoped per organization, consistent with existing `organizations_and_servers` policies.

## Non-goals

- Long-term retention / archival tiers (cloud edition, later).
- Raw-log upload (explicitly opt-in, separate PRD if ever).
- Realtime fan-out UX (covered by [[10-dashboard-detections-feed]]).

## Current state

- `apps/web/src/app/api/events/route.ts` and `servers/[id]/events/route.ts` exist — confirm shape and whether they persist anywhere durable.
- `supabase/migrations/20260412000000_organizations_and_servers.sql` defines `organizations`, `organization_members`, `servers`.
- Daemon emits to alerts (`apps/cli/src/daemon/alerts/`) and a `runs-worker`, but detections are not persisted to a server-side detections table.

## Data model

New migration `*_detection_core.sql` adding (mirrors `docs/PRD.md`):

- `detections` — id, organization_id, server_id, rule_id, severity, title, description, source_ip, username, raw_metadata_json, detected_at, status (new/acknowledged/resolved).
- `remediation_actions` — id, org, server, detection_id, action_type, target_value, status, executed_at, expires_at, metadata_json.
- `hardening_findings` — id, org, server, finding_key, severity, status, title, recommendation, observed_at, resolved_at.
- `allowlists` — id, org, type (ip/cidr/user), value, note, created_at.
- `alert_destinations` — id, org, type, config_json, created_at. *(detail in [[08-alerting-and-alert-rules]])*
- `alert_rules` — id, org, name, min_severity, server_scope_json, destination_id. *(detail in [[08-alerting-and-alert-rules]])*
- `rule_registry` — id, rule_id, version, title, category, source_path, enabled_by_default, created_at. *(detail in [[01-detection-rule-engine]])*

All org-scoped tables get RLS mirroring existing patterns; agent writes go through the service role behind the API, not anon.

## API

- `POST /api/events` — accept a batch of normalized detection + heartbeat payloads; validate against a shared zod schema (sourced from `apps/sdk`); upsert into `detections` / update `servers.last_seen_at`.
- `POST /api/heartbeat` (or fold into events) — server status + metadata.
- `GET /api/servers/[id]/detections`, `/findings`, `/remediations` — read endpoints for the dashboard.
- Auth: signed agent enrollment token / API key per server (PRD §9). Reuse existing enrollment if present, else define.

## Acceptance criteria

- [ ] Migration applied; tables exist with RLS verified (no cross-org leakage).
- [ ] Daemon can POST a normalized detection and it appears in `detections`.
- [ ] Shared payload schema lives in `apps/sdk` and is imported by both web API and CLI.
- [ ] No raw log lines are stored unless explicitly opted in.

## Out of scope / later

- Retention policies, partitioning, archival.

## Open questions

- Reuse existing `properties`/`property_runs` semantics or keep detections fully separate? (Recommend separate — different lifecycle.)
- Is there an existing agent enrollment token mechanism to reuse for ingest auth?
</content>
