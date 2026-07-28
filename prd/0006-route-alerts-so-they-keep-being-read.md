---
openprd: "0.2"
id: "0006"
title: "Route alerts so they keep being read"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: alert-system, routing, deduplication, escalation, notifications, modules
supersedes:
superseded-by:
---

## Problem

**Every module already depends on this one, and it does not exist.** `spend-guard`
routes through `alert-system` in its `mod.toml`; `code-scanner` calls
`ctx.alert()` in all four subsystems. The SDK defines the `Alert` shape, so the
calls compile and the daemon runs — but there is nothing behind them deciding
where an alert goes, whether it is a duplicate, or whether it is worth waking
someone. That gap is invisible until the day it matters.

**Alert fatigue is not a UX problem, it is the primary failure mode of the
entire product.** A detection nobody reads is identical to a detection that
never fired, so every module's careful work on precision — `deps` collapsing
overlapping rules, `secrets` refusing to report AWS documentation keys, `sast`
capping pattern-only findings at medium — is wasted if the routing layer
undoes it by sending 400 messages to one Slack channel.

**The hard parts are deduplication and escalation, not delivery.** Posting to a
webhook is trivial. Knowing that this alert is the same incident as the one 40
minutes ago, that it has since become more severe, that the operator is asleep
and it can wait until morning, or that it has fired every hour for a week and
should stop — that is the product.

## Goals

- An operator receives **one message per incident**, not per detection event.
- **Severity determines channel and urgency**, so a critical reaches someone
  awake and an informational does not.
- A recurring, unacknowledged condition **escalates rather than repeats**.
- Delivery failure is itself visible: an alert that could not be sent must not
  vanish.
- Modules stay simple — they call `ctx.alert()` and this layer decides
  everything else.

## Non-Goals

- **Not an incident-management platform.** On-call rotations, scheduling and
  acknowledgement workflows belong to PagerDuty; integrate, do not reimplement.
- **Not a SIEM.** Long-term event storage and correlation across hosts is a
  different product; this routes what modules produce.
- **Not per-module notification config.** Modules describe severity and
  content; routing policy lives here, or every module reimplements it slightly
  differently.

## Users

- **Solo operators** who need the phone to ring for a compromise and stay
  silent for a hardening suggestion.
- **Small teams** routing by severity to different channels.
- **Anyone who has muted a monitoring tool** — the population this is designed
  around.

## Requirements

- R1 [P0] **Destinations**: Slack, Discord, generic webhook, email (SMTP),
  syslog, PagerDuty. Each independently configured and independently failable.
- R2 [P0] **Severity-based routing**: map each severity to zero or more
  destinations, so `info` can go to syslog only and `critical` to PagerDuty.
- R3 [P0] **Deduplication by incident identity**, not by message text. An
  incident key is (module, subject, detector); the same key within a window
  updates rather than repeats.
- R4 [P0] **Escalation on change, not on repetition.** A condition that worsens
  re-notifies; a condition that merely persists does not.
- R5 [P1] **Quiet hours** with a severity floor that ignores them.
- R6 [P1] **Rate limiting per destination**, with a summary message when the cap
  is hit — never silent truncation.
- R7 [P0] **Delivery failures are alerts.** A webhook returning 500 must surface
  somewhere, or the system is silently deaf.
- R8 [P1] **Digest mode**: batch below-threshold alerts into a periodic summary.
- R9 [P2] **Acknowledgement** via a link or CLI, suppressing an incident until
  it changes.

## UX Notes

```toml
[alert-system]
enabled = true

[alert-system.routing]
critical = ["pagerduty", "slack"]
high     = ["slack"]
medium   = ["slack"]
low      = ["syslog"]
info     = ["syslog"]

[alert-system.dedupe]
window = "6h"
escalate_on_severity_change = true

[alert-system.quiet_hours]
from = "22:00"
to   = "07:00"
floor = "critical"        # criticals ignore quiet hours
```

```bash
threatcrush alerts test --severity critical   # prove the path end to end
threatcrush alerts recent                     # what fired, and where it went
threatcrush alerts ack <incident>
```

Design constraint: **the test command matters more than it looks.** An alerting
path is usually discovered to be broken at the moment it is needed, so proving
it works must be one command.

## Success Metrics

- A 48-hour ongoing condition produces **one** notification plus escalations,
  not one per scan interval.
- Zero silent delivery failures: every failed send appears somewhere.
- `alerts test` exercises the real path, including credentials, in <5s.
- Operators keep the integration enabled after 30 days — the only metric that
  really matters, and the one this module exists to protect.

## Risks & Open Questions

- **Dedupe that is too aggressive hides a second, real incident** behind the
  first. Incident identity must include enough to distinguish them, and
  over-merging is worse than a duplicate message.
- **Credentials for six destinations** make this module a high-value target on
  the host. They should resolve from the secret store rather than sit in config.
- **Quiet hours are a loaded gun.** A misconfigured floor silences a compromise
  until morning. **Open:** should quiet hours require an explicit floor, with no
  default, so the choice is always deliberate?
- **Open:** should modules be able to suggest a destination, or is routing
  policy exclusively the operator's? Suggesting risks every module claiming to
  be critical.
