---
openprd: "0.2"
id: "0015"
title: "Report abuse without becoming a source of it"
status: In Progress
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: [abuse-reporter, abuseipdb, reputation, false-positives, modules]
supersedes:
superseded-by:
---

## Problem

Attack sources are usually compromised third-party machines — a hacked VPS, an
infected home router, a misconfigured cloud instance. Their owners generally do
not know. Reporting to the hosting provider is the only mechanism that gets the
machine cleaned up rather than merely blocked, and shared reputation feeds like
AbuseIPDB are how small operators benefit from each other's observations.

**The problem is that an automated reporter is a machine that makes public
accusations about other people's infrastructure.** Every failure mode is
someone else's problem:

- **Shared and rotating addresses.** Reporting a CGNAT range, a corporate NAT
  gateway or a cloud egress IP attributes an attack to thousands of innocent
  users, and reputation feeds propagate it far beyond the reporter.
- **Spoofed sources.** An attacker who can generate traffic appearing to come
  from a competitor can weaponize an automated reporter into a distributed
  reputation attack. **The reporter becomes the abuse.**
- **Ordinary background noise.** Internet-facing hosts see constant low-grade
  scanning. Reporting all of it is noise that degrades the feeds everyone
  depends on.

That is why this module's central requirement is a **high evidentiary bar**,
not throughput.

## Goals

- Genuinely malicious, **confirmed** sources are reported so they get cleaned
  up, not merely blocked locally.
- **False reports are structurally hard to produce**: only corroborated,
  connection-verified activity is reportable.
- The operator can see exactly what was reported about whom, and retract it.
- Reporting is **opt-in and off by default**, because it is an outbound public
  statement made in the operator's name.

## Non-Goals

- **Not blocking** — `firewall-rules` (PRD 0010) does that locally.
- **Not retaliation.** Nothing is ever sent *at* a source. Scanning back,
  probing or counter-attacking is out of scope permanently and non-negotiably.
- **Not legal action support.**
- **Not a reputation feed of its own.** Contribute to existing ones.

## Users

- **Operators who want compromised hosts fixed**, not just blocked.
- **Community-minded small teams** contributing to shared feeds they benefit
  from.

## Requirements

### Evidence bar

- R1 [P0] **Only corroborated sources are reportable.** A source must be
  confirmed by a detector whose precision justifies a public accusation —
  `honeypot` (PRD 0012) interaction, a successful-attack log entry
  (PRD 0009 R4), or repeated authentication failure over a sustained window. A single
  ambiguous signal is never enough.
- R2 [P0] **Connection-verified only.** Reportable activity must have involved a
  completed TCP handshake, which makes trivially spoofed sources unreportable.
  This is the structural defence against being weaponized.
- R3 [P0] **Never report**: private ranges, the protected set from PRD 0010,
  known CGNAT and carrier ranges, cloud provider metadata endpoints, or any
  address the operator has allowlisted.
- R4 [P0] **Rate limits per source and globally**, so a misconfiguration cannot
  produce a flood of accusations.
- R5 [P1] **Cooling-off period** before a first-time source is reported, so a
  single burst does not immediately become a public record.

### Report

- R6 [P0] **AbuseIPDB** as the reference integration, with category mapping and
  evidence in the comment field.
- R7 [P1] Additional destinations: provider abuse contacts resolved via RDAP,
  Spamhaus.
- R8 [P0] **Evidence is included and is redacted.** Reports must not carry the
  operator's own hostnames, paths, credentials or customer data. What leaves the
  host is a public statement and must be reviewed as one.
- R9 [P0] **Local audit trail** of everything reported, with the evidence that
  justified it.

### Control

- R10 [P0] **Off by default**, with an explicit opt-in that states plainly what
  will be sent and to whom.
- R11 [P0] **Dry-run mode** showing exactly what would be reported, and it is
  the default on first enable.
- R12 [P1] **Retraction**: a command to withdraw a report, because the module
  will eventually be wrong and the operator needs a way to fix it.

## UX Notes

```toml
[abuse-reporter]
enabled = false             # opt-in: this makes public statements in your name
mode = "dry_run"
destinations = ["abuseipdb"]
min_corroborating_signals = 2
cooling_off = "1h"
never_report = ["203.0.113.0/24"]
redact_evidence = true
```

```bash
threatcrush abuse pending      # what would be reported, and on what evidence
threatcrush abuse history
threatcrush abuse retract <id>
```

## Success Metrics

- **Zero reports** for spoofable, private, protected or carrier-range sources —
  asserted by test, since these are the cases that harm third parties.
- 100% of reports carry ≥2 corroborating signals and a completed handshake.
- Evidence redaction verified: no hostname, path or credential from the
  reporting host appears in any submitted report.
- Dry-run is the default on first enable, and produces the same output the live
  mode would send.

## Risks & Open Questions

- **This module can harm innocent third parties**, and unlike every other module
  here the damage lands outside the operator's own systems. The evidence bar,
  the handshake requirement and dry-run-by-default are the mitigations, and none
  of them are optional.
- **Reputation feeds are slow to forget.** A false report can outlive its
  retraction. That asymmetry argues for a conservative bar even at the cost of
  under-reporting real abuse.
- **The operator is publicly the reporter**, not ThreatCrush. Their API key,
  their name, their reputation. The opt-in text must make that unmistakable.
- **Open:** should reporting require an explicit per-source confirmation for the
  first N reports, so an operator sees the module's judgement before trusting it
  unattended?
- **Open:** is RDAP-resolved provider email worth implementing, given abuse
  mailboxes are frequently unmonitored and auto-mailing them borders on noise?

## Implementation (2026-10-17)

The reporting engine has landed in `apps/cli`:

- `daemon/workers/abuse-reporter.ts` — a bus worker (mirror of `CloudSync`) that
  queues blocked sources and reports the ones that clear the bar, off the ban
  path.
- `daemon/workers/abuse-evidence.ts` — the bar as pure, tested functions:
  never-report ranges (private, CGNAT 100.64/10, reserved, operator), the
  connection-verified (R2) requirement, corroboration count (R1), cooling-off
  (R5), and AbuseIPDB category mapping.
- `daemon/workers/abuse-destinations.ts` — AbuseIPDB (R6) and StopForumSpam (R7)
  clients, with the comment generated from the evidence shape so no hostname,
  path or credential can leak (R8).
- `core/abuse-report-log.ts` + `commands/abuse.ts` — the local audit trail (R9),
  `threatcrush abuse status|history|pending|retract` (R11/R12).

**Owner decision overriding R10/R11.** Shipped **enabled and `mode = "live"` by
default**, not off/dry-run, at the owner's direction (2026-10-17). The
third-party-safety mitigations are kept non-negotiable regardless: the evidence
bar (R1–R3), rate limits (R4) and cooling-off (R5) always apply, and the worker
is **inert until an API key is present** — with no `ABUSEIPDB_API_KEY` it loads,
logs once and reports nothing. So "on by default" means it activates the moment
a key is provisioned to a box, not that a stock install makes accusations.

**Still open / follow-up:** RDAP provider-abuse email (R7); a public,
key-gated blocklist feed and the `threatcrush.com/traffic` wall that consumes
these reports; provisioning AbuseIPDB + StopForumSpam accounts and keys into the
fleet vault.
