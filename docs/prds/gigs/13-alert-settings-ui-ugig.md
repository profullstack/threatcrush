# Build the ThreatCrush alert settings UI

> ugig.net gig posting — implements [PRD-13](../13-alert-settings-ui.md)

- **Title:** Build the ThreatCrush alert settings UI
- **Skills required:** `typescript`, `react`, `nextjs`, `tailwind`, `supabase`, `frontend`, `security`
- **Budget type:** fixed
- **Budget (USD):** 1,200 – 2,000
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/alert-settings-ui`
- **Spec:** `docs/prds/13-alert-settings-ui.md`

## What we need

Alerting can only be configured by hand-editing `threatcrushd.conf` per host.
Build the dashboard UI to manage alert destinations and rules centrally. Pairs
with the alerting engine (PRD-08).

## Scope

1. Destinations CRUD (Slack, Discord, email, webhook, PagerDuty) with
   type-specific config forms; secrets encrypted at rest, never returned in
   plaintext (reuse the existing client-side secret-encryption pattern).
2. Rules CRUD: name, min severity, server scope (all / selected), destination
   mapping.
3. "Send test alert" per destination; URL validation before save.
4. `GET/POST/PATCH/DELETE …/alert-destinations` + `…/alert-rules`,
   `…/alert-destinations/[id]/test`. Role-gated.

## Acceptance criteria

- Operator adds a Slack/Discord/PagerDuty destination and sends a test.
- A rule routes only matching detections to the chosen destination.
- Secrets stored encrypted. PR with green CI.
