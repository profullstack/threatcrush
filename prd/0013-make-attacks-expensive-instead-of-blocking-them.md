---
openprd: "0.2"
id: "0013"
title: "Make attacks expensive instead of blocking them"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: tar-pit, throttling, cost-asymmetry, containment, modules
supersedes:
superseded-by:
---

## Problem

Blocking has a tell. An attacker whose connection is refused learns immediately
that they were detected, and rotates to another address — which on a botnet
costs nothing. PRD 0010 exists and is worth having, but a block ends the
engagement on the attacker's terms and teaches them what tripped it.

**Slowing them down instead inverts the economics.** A connection held open for
thirty seconds instead of refused in one costs the attacker a worker, a socket
and a timeout, while costing the defender almost nothing. Against a scanner
working through a list, being slow is worse than being closed: closed is a fast
negative result, slow ties up capacity and yields nothing. It also **delays the
feedback signal** an attacker needs to tune their approach.

This is a genuinely different response class from blocking, and it fits between
"alert only" and "block": useful precisely in the cases where confidence is
moderate — where blocking risks collateral damage but doing nothing feels wrong.

The obvious hazard is that a mechanism for holding connections open can exhaust
the defender's own resources. A tar-pit that consumes a file descriptor and a
thread per attacker has simply moved the denial of service to the defender.

## Goals

- A suspicious source's throughput drops sharply, without an explicit refusal
  that signals detection.
- Resource cost to the defender is **bounded and predictable**, and always well
  below the cost imposed on the attacker.
- Available as a **middle response** for moderate-confidence detections, where
  blocking is too blunt.
- Legitimate traffic is never tar-pitted; when in doubt, do nothing.

## Non-Goals

- **Not DDoS mitigation.** Volumetric attacks are absorbed upstream; holding
  connections open under a real flood is exactly wrong.
- **Not a replacement for blocking.** High-confidence sources should be blocked
  by `firewall-rules` (PRD 0010).
- **Not a proxy.** No legitimate traffic passes through this module.
- **Not retaliation.** Slowing an attacker is defensive; anything that sends
  traffic *at* them is not, and is out of scope permanently.

## Users

- **Solo operators** who want brute force to become useless without risking a
  block on a shared address.
- **Platform engineers** wanting a graduated response instead of a binary one.

## Requirements

- R1 [P0] **Connection-level delay** for flagged sources: accept, then respond
  slowly — byte-at-a-time banners, long inter-packet gaps, delayed handshake
  completion.
- R2 [P0] **Hard resource ceiling**: a maximum number of concurrent tar-pitted
  connections and a maximum lifetime each. On reaching the ceiling, stop
  tar-pitting new sources rather than degrading the host. **The defender's
  resource budget is never negotiable.**
- R3 [P0] **Non-blocking implementation.** Event-driven with no thread or
  process per connection; a tar-pit that costs a thread per attacker is a
  self-inflicted denial of service.
- R4 [P0] **Protected sources are never tar-pitted**, sharing the protected set
  from `firewall-rules` (PRD 0010 R1) so there is one place to get this right.
- R5 [P1] **Graduated response**: delay proportional to accumulated suspicion,
  so a borderline source is slowed slightly and a confirmed one crawls.
- R6 [P1] **TCP-level tarpitting** (zero window) where supported, which is far
  cheaper than application-level holding.
- R7 [P0] **Automatic release** on a timer, like every rule in PRD 0010.
- R8 [P1] Report time wasted per source through `alert-system` — the module's
  value is legible only as an aggregate.

## UX Notes

```toml
[tar-pit]
enabled = true
max_concurrent = 200        # hard ceiling; new sources are ignored beyond it
max_connection_lifetime = "60s"
delay_ms = 2000
release_after = "30m"
```

```bash
threatcrush tar-pit status     # who is stuck, for how long, at what cost
```

```
[INFO] tar-pit · 14 sources held

  203.0.113.9   41m held   612 connections consumed   0.3 MB defender cost
  198.51.100.4  22m held   287 connections consumed

  Top source has spent roughly 7 worker-hours on connections that go nowhere.
```

## Success Metrics

- Defender cost per tar-pitted connection **<10 KB memory and no dedicated
  thread**, verified under load.
- 200 concurrent tar-pitted connections sustained with negligible CPU.
- Attacker connection lifetime increased ≥30× versus a refused connection.
- Zero legitimate connections tar-pitted in a week of production traffic.
- The ceiling holds under a flood: beyond `max_concurrent`, new sources are
  ignored and the host stays healthy.

## Risks & Open Questions

- **Self-inflicted resource exhaustion is the defining risk**, which is why the
  ceiling (R2) and the non-blocking requirement (R3) are P0 rather than tuning.
- **Under a real flood, tar-pitting is actively harmful** — it holds open
  exactly what the attacker wants held open. **Open:** should the module
  auto-disable above a connection-rate threshold and defer to blocking?
- **Some legitimate clients retry aggressively** when slow, amplifying rather
  than reducing load. Health checks and uptime monitors are the likely victims
  and belong in the protected set.
- **Moderate confidence is doing a lot of work here.** The module is most useful
  exactly where the detection is least certain, which means it will sometimes
  slow real users. The graduated response limits the damage; it does not remove
  it.
- **Open:** is TCP zero-window tarpitting portable enough to rely on, or does
  the application-level path have to carry the feature everywhere?
