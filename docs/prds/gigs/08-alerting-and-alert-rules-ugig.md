# Build ThreatCrush alerting channels & alert rules

> ugig.net gig posting — implements [PRD-08](../08-alerting-and-alert-rules.md)

- **Title:** Build ThreatCrush alerting channels & alert rules
- **Skills required:** `typescript`, `nodejs`, `slack-api`, `discord-api`, `pagerduty`, `supabase`, `security`
- **Budget type:** fixed
- **Budget (USD):** 1,500 – 2,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/alerting-rules`
- **Spec:** `docs/prds/08-alerting-and-alert-rules.md`

## What we need

The README promises Slack, Discord, email, webhook, and PagerDuty alerts, but the
daemon ships only SMTP/webhook/Slack and has no alert-rules layer (no
thresholding, severity filtering, per-server subscriptions, or rate limiting).
Add the missing channels and the rules engine behind them.

## Scope

1. New channels: Discord webhook + PagerDuty Events API (keep Slack/webhook/SMTP)
   in `apps/cli/src/daemon/alerts`.
2. `alert_destinations` + `alert_rules` (PRD-00) as the backing model; routing: a
   detection matches 0..n rules → fan out to mapped destinations.
3. Rate limiting + thresholding per rule/destination; coalesce bursts.
4. Config sync: daemon reads org-scoped rules from the server, falls back to
   `threatcrushd.conf` for local-only mode.

## Acceptance criteria

- Discord + PagerDuty deliver a test alert.
- A medium-severity detection does not page a high-only rule; per-server
  subscription routes only that server's alerts; a flood is capped to the limit.
- PR with green CI.
