# PRD — Alerting channels & alert rules

- **Status:** Draft · Not started
- **Surface(s):** CLI (`apps/cli/src/daemon/alerts`), Web (alert config) + DB
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §7 "Alerting" · README "Real-time Alerts (Slack, Discord, email, webhook, PagerDuty)" · [[00-detection-data-model]] · [[13-alert-settings-ui]]

## Problem

The README's alert table promises **Slack, Discord, email, webhook, PagerDuty**,
but the daemon ships only `smtp`, generic `webhook`, and `slack` channels
(`apps/cli/src/daemon/alerts/index.ts`). More importantly there is **no alert
rules layer** — the PRD requires thresholding, severity filtering, per-server
subscriptions, and rate limiting, and there are no `alert_rules` /
`alert_destinations` tables. Today alerting is fire-on-severity with no operator
control, which means either noise or missed alerts.

## Goals

1. Add the missing channels: **Discord**, **PagerDuty** (Slack/webhook/email exist).
2. Introduce an alert-rules layer: min severity, server scope, per-destination routing.
3. Rate limiting + thresholding to control noise (complements detection suppression).
4. Back it with `alert_destinations` + `alert_rules` tables ([[00-detection-data-model]]).

## Non-goals

- Inbound chatops (query state from Slack/Discord) — `chat/bot` is `not-started` in `docs/SURFACES.md`.
- On-call scheduling (PagerDuty owns that).

## Current state

- `apps/cli/src/daemon/alerts/index.ts`: `smtp`, `webhook`, `slack` channels.
- No alert rules; severity threshold is hardcoded (alerts emit when severity ≥ high per `docs/SURFACES.md`).
- No DB tables for destinations/rules.

## Requirements

1. **Channels**: add Discord webhook + PagerDuty Events API; keep Slack/webhook/SMTP.
2. **Destinations**: `alert_destinations` (type + config_json), managed from the dashboard ([[13-alert-settings-ui]]) and/or `threatcrushd.conf`.
3. **Rules**: `alert_rules` (name, min_severity, server_scope_json, destination_id).
4. **Rate limiting**: per-rule/per-destination caps; coalesce bursts.
5. **Routing**: a detection matches 0..n rules → fan out to mapped destinations.
6. **Config sync**: daemon reads rules from server (org-scoped) and/or local conf for local-only mode.

## Acceptance criteria

- [ ] Discord + PagerDuty channels deliver a test alert.
- [ ] A medium-severity detection does not page a high-only rule.
- [ ] Per-server subscription routes only that server's alerts.
- [ ] Rate limit caps a flood to the configured ceiling.

## Out of scope / later

- Inbound bot commands.
- Alert digests / daily summary email (nice fast-follow; PRD mentions daily summary).

## Open questions

- Local-only mode: rules from `threatcrushd.conf` only, or also cached from server? (Recommend: conf is source of truth when not enrolled.)
</content>
