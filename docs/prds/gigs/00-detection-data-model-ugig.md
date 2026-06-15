# Build the ThreatCrush detection data model & event ingest

> ugig.net gig posting — implements [PRD-00](../00-detection-data-model.md)

- **Title:** Build the ThreatCrush detection data model & event ingest
- **Skills required:** `postgres`, `supabase`, `sql`, `rls`, `typescript`, `nextjs`, `zod`, `api-design`
- **Budget type:** fixed
- **Budget (USD):** 1,200 – 2,000
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/detection-data-model`
- **Spec:** `docs/prds/00-detection-data-model.md`

## What we need

The backbone every other detection feature depends on. ThreatCrush's shipped
schema has servers/properties but **none** of the detection tables the product
is built around. We need the data model plus one authenticated, normalized
ingest path the daemon writes to — privacy-first (normalized detections only, no
raw logs by default).

## Scope

1. One Supabase migration adding `detections`, `remediation_actions`,
   `hardening_findings`, `allowlists`, `alert_destinations`, `alert_rules`,
   `rule_registry` (columns per the PRD), org-scoped with RLS that mirrors the
   existing `organizations_and_servers` policies.
2. `POST /api/events` — validate a batch of normalized detection + heartbeat
   payloads against a shared zod schema (exported from `apps/sdk`), upsert into
   `detections`, update `servers.last_seen_at`. Agent auth via the existing
   server enrollment token / API key.
3. Read endpoints: `GET /api/servers/[id]/detections|findings|remediations`.
4. The shared payload schema lives in `apps/sdk` and is imported by both the web
   API and the CLI (no duplicate definitions).

## Acceptance criteria

- Migration applies cleanly; RLS verified with a cross-org test (no leakage).
- Daemon can POST a normalized detection and it appears in `detections`.
- No raw log lines are stored unless explicitly opted in.
- PR with green CI and the shared schema wired into both web + CLI.
</content>
