---
openprd: "0.2"
id: "0010"
title: "Block attackers without locking out the operator"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: firewall-rules, blocking, nftables, iptables, containment, modules
supersedes:
superseded-by:
---

## Problem

This is the first module that **changes the system rather than observing it**,
and that single fact dominates its design. Every other module's worst failure is
a missed detection or a noisy alert. This module's worst failure is **locking
the operator out of their own server at 3am from a false positive**, or blocking
the customers it was bought to protect.

The value is real: `ssh-guard`, `log-watcher` and `network-monitor` all produce
sources worth blocking, and a block is the only response that actually stops an
in-progress attack. But three things make automated blocking dangerous in
practice:

**Self-lockout.** The operator's own address, the CI runner's, the load
balancer's, and the monitoring probe's all look like traffic. A rule that blocks
one of them is an outage caused by the security tool.

**Shared addresses.** Blocking a NAT gateway, a mobile carrier CGNAT range or a
corporate egress IP blocks everyone behind it. On IPv4 the attacker frequently
does not have an address of their own.

**Rules that outlive their reason.** A ban list that only grows becomes an
unexplained, unreviewable accretion — and eventually blocks something important
for a reason nobody remembers.

## Goals

- An in-progress attack is stopped **in seconds**, without human involvement.
- **Self-lockout is structurally impossible**: protected addresses can never be
  blocked, whatever any detector says.
- Every rule is **reversible, attributed and expiring** — it records who added
  it, why, on what evidence, and when it disappears.
- The module's changes are **visible and undoable in one command**, because the
  moment an operator needs that, they need it urgently.

## Non-Goals

- **Not a firewall manager.** Base policy, port rules and zones stay the
  operator's; this adds and removes dynamic blocks in its own chain and touches
  nothing else.
- **Not a detector.** Sources come from other modules; this executes.
- **Not DDoS mitigation.** Volumetric attacks are absorbed upstream, not on the
  host.
- **Not permanent blocklists.** Everything expires.

## Users

- **Solo operators** who want brute force stopped without watching for it.
- **Platform engineers** who need to see exactly what an agent changed.
- **Incident responders** containing an active attack, then undoing it cleanly.

## Requirements

### Safety first

- R1 [P0] **Protected set that can never be blocked**: explicitly configured
  addresses, the current SSH client's address at daemon start, loopback, private
  ranges by default, and the default gateway. Enforced at the point of writing a
  rule, not at the point of deciding — so no detector, however wrong, can
  produce a lockout.
- R2 [P0] **Every rule expires.** A TTL is mandatory; there is no permanent
  block, only renewal on repeat offence.
- R3 [P0] **Dedicated chain/table.** All rules live in a ThreatCrush-owned
  chain, so `flush` removes exactly what this module added and nothing else.
- R4 [P0] **Dry-run mode** that logs the rule it would write, and is the default
  on first install.
- R5 [P0] **Rules survive daemon restart** but not their TTL, and are
  reconciled at start — a stale rule from a crashed daemon must not persist
  indefinitely.

### Act

- R6 [P0] **nftables and iptables** backends, detected at runtime; refuse to run
  rather than guess if neither is manageable.
- R7 [P0] **IPv4 and IPv6 parity.** A v4-only block on a dual-stack host is a
  block an attacker steps around by reconnecting over v6 — a false sense of
  containment is worse than none.
- R8 [P1] **Escalating durations** for repeat offenders.
- R9 [P1] **Subnet blocking** with a deliberately high threshold, given the
  shared-address risk.
- R10 [P1] **Rate limiting** as a softer response than a block.

### Explain

- R11 [P0] Every rule records: source, reason, detecting module, evidence
  reference, added-at, expires-at.
- R12 [P0] `threatcrush firewall list` / `unblock <ip>` / `flush`, all
  single-command.
- R13 [P1] Alert on every block through `alert-system` (PRD 0006), so blocking
  is never silent.

## UX Notes

```toml
[firewall-rules]
enabled = true
mode = "dry_run"                 # dry_run | enforce — dry_run is the default
backend = "auto"
default_ttl = "1h"
max_ttl = "24h"
protected = ["203.0.113.7/32"]   # never blocked, whatever any detector says
protect_current_ssh_client = true
ipv6 = true
```

```bash
threatcrush firewall list        # what is blocked, why, and until when
threatcrush firewall unblock 203.0.113.9
threatcrush firewall flush       # remove everything this module added
```

Design constraints:

- **`dry_run` is the install default.** An operator should see what it *would*
  do for a week before it does anything.
- **`flush` must be reliable and obvious.** It is the command someone runs while
  panicking.

## Success Metrics

- **Zero self-lockouts.** Asserted by test: a block request for a protected
  address is refused at the write layer, not merely filtered earlier.
- Rules expire on schedule, including after a daemon crash and restart.
- v4 and v6 rules created together on a dual-stack host, always.
- `flush` removes 100% of this module's rules and 0% of the operator's.
- Block applied within 5 seconds of a detection.

## Risks & Open Questions

- **This module can cause the outage.** That is the entire risk register. The
  mitigations — dry-run default, protected set enforced at the write layer,
  mandatory TTL, one-command flush — are not optional features.
- **Shared IPs mean collateral damage** that is invisible to the operator: the
  blocked customer simply sees a broken site and leaves. **Open:** should the
  module consult an ASN/CGNAT dataset and refuse to block known carrier ranges?
- **Cloud firewalls sit outside the host.** On AWS/GCP the security group may be
  the real boundary; host rules are still useful but are not the whole picture.
- **An attacker who can trigger detections can weaponize the blocker** —
  spoofing traffic that appears to come from a partner's IP to have it blocked.
  The protected set mitigates the important cases; it does not solve the general
  problem. **Open:** should blocking require corroboration from two detectors?
