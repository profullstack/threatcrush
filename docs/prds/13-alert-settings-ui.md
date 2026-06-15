# PRD — Alert settings UI

- **Status:** Draft · Not started
- **Surface(s):** Web/PWA (`apps/web/src/app/org/[slug]/settings`)
- **Priority:** P1
- **Owner:** TBD
- **Related:** `docs/PRD.md` §5 → Alert settings · [[08-alerting-and-alert-rules]] · [[00-detection-data-model]]

## Problem

Alerting can only be configured by hand-editing `threatcrushd.conf` on each host.
The dashboard has no UI to manage alert destinations or rules, so an operator
cannot centrally control where alerts go or filter them. This pairs with
[[08-alerting-and-alert-rules]] (the engine + tables) to make alerting usable.

## Goals

1. Manage `alert_destinations` (Slack, Discord, email, webhook, PagerDuty) from the dashboard.
2. Manage `alert_rules` (name, min severity, server scope, destination).
3. Send a test alert per destination.
4. Org-role gated.

## Non-goals

- Inbound chatops.
- Per-user notification preferences (org-level first).

## Current state

- `org/[slug]/settings/page.tsx` exists (scope unknown — audit before building).
- No destinations/rules UI; no backing tables yet (see [[00-detection-data-model]]).

## Requirements

1. **Destinations CRUD**: add/edit/remove, type-specific config form, secret handling (encrypted at rest).
2. **Rules CRUD**: min severity, server scope (all / selected), destination mapping.
3. **Test button**: send a sample alert through a destination.
4. **Validation**: verify webhook/Slack URLs before save.

## API

- `GET/POST/PATCH/DELETE /api/orgs/[id]/alert-destinations`
- `GET/POST/PATCH/DELETE /api/orgs/[id]/alert-rules`
- `POST …/alert-destinations/[id]/test`

## Acceptance criteria

- [ ] Operator can add a Slack/Discord/PagerDuty destination and send a test.
- [ ] A rule routes only matching detections to the chosen destination.
- [ ] Secrets stored encrypted; never returned in plaintext to the client.

## Out of scope / later

- Per-user prefs, digest scheduling UI.

## Open questions

- Reuse the existing client-side secret encryption pattern (see module secrets) for destination configs?
</content>
