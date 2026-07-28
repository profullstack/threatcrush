---
openprd: "0.2"
id: "0011"
title: "Catch the exfiltration channel that survives egress filtering"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: dns-monitor, exfiltration, tunneling, dga, c2, modules
supersedes:
superseded-by:
---

## Problem

DNS is the one protocol almost nobody blocks. A host that cannot reach the
internet on any other port can usually still resolve names — which is precisely
why DNS is the durable channel for **command-and-control and data
exfiltration**. A compromised process encodes data into subdomain labels,
queries a domain the attacker controls, and reads instructions back from the
answers. No outbound TCP connection appears anywhere.

This makes DNS the blind spot in the coverage the other modules provide:
`network-monitor` sees a connection to the local resolver and nothing more;
`log-watcher` sees nothing at all; egress firewall rules permit it by design.

The detectable signatures are distinctive, which is what makes a narrow module
worthwhile:

- **Tunneling**: abnormally long or high-entropy labels, unusual record types
  (`TXT`, `NULL`), and a query rate to one domain far above anything a human
  browsing produces.
- **DGA**: bursts of algorithmically-generated names with high `NXDOMAIN` rates,
  as malware hunts for whichever rendezvous domain is currently registered.
- **Newly-observed domains** contacted by a server process that has resolved the
  same handful of names for months.

## Goals

- DNS tunneling from a compromised host is detected within minutes, before a
  meaningful volume of data leaves.
- DGA behaviour is distinguished from ordinary resolution failure.
- A **new domain** contacted by a server workload is surfaced, since servers
  have far more predictable resolution patterns than user machines.
- Operates without a resolver plugin where possible, so it works on hosts using
  systemd-resolved, dnsmasq or a cloud resolver.

## Non-Goals

- **Not a DNS server or filtering resolver.** Pi-hole and NextDNS block; this
  observes.
- **Not blocklist-based content filtering.** Ad and tracker blocking is a
  different product.
- **Not DNSSEC validation.**
- **Not blocking** — `firewall-rules` (PRD 0010) acts if configured.

## Users

- **Solo operators** running application servers, whose DNS should be boring
  and predictable.
- **Platform engineers** watching for C2 across a fleet.
- **Incident responders** determining whether data left, and where to.

## Requirements

### Observe

- R1 [P0] **Query capture** from whichever source is available: systemd-resolved
  logs, dnsmasq logs, a local resolver's query log, or packet capture on port 53
  where permitted. **State which source is in use** — coverage differs sharply
  between them and an operator must know what is not being seen.
- R2 [P0] Extract query name, type, response code and the querying process where
  the source allows attribution.
- R3 [P0] Honest degradation: if no source is available the module reports that
  it cannot observe, rather than reporting nothing found.

### Detect

- R4 [P0] **Tunneling heuristics**: label length above a threshold, high entropy
  in labels, sustained query rate to a single registered domain, and a high
  proportion of `TXT`/`NULL` records. Individually weak, jointly strong —
  require a combination before alerting.
- R5 [P0] **DGA detection**: `NXDOMAIN` rate and burst pattern, plus character
  distribution unlike natural language.
- R6 [P1] **New-domain detection** against a learned baseline, weighted by the
  querying process. A database process resolving a new domain is far more
  interesting than a browser doing so.
- R7 [P1] **Volume anomaly** per process and per domain against baseline.
- R8 [P2] Optional threat-intelligence correlation for known C2 domains, kept
  optional because feeds age badly and create a false sense of coverage.

### Report

- R9 [P0] Route through `alert-system` (PRD 0006), leading with **what left**,
  estimated where possible: query count, bytes encoded, destination domain.
- R10 [P1] Dedupe per (domain, detector) so a long-running tunnel produces one
  incident with escalation, not one alert per query.

## UX Notes

```bash
threatcrush dns-monitor top          # most-queried domains, by process
threatcrush dns-monitor baseline
threatcrush dns-monitor source       # what is being read, and what is missed
```

```
[CRITICAL] dns-monitor · probable DNS tunnel

  domain: x7k2.exfil.example        queries: 4,182 in 11m
  labels avg 47 chars, entropy 4.6 bits/char, 96% TXT
  process: node (pid 3311)

  Roughly 180 KB encoded outbound. This does not resemble name resolution.

  Now: isolate the process. DNS is not blocked by your egress rules.
```

## Success Metrics

- Tunneling detected within 5 minutes on a fixture generating iodine/dnscat-style
  traffic.
- Zero alerts from ordinary resolution — CDNs, package registries, telemetry —
  over a week on a normal host.
- DGA fixture detected with <1 false positive per host per week.
- The active capture source is always reported, including "none available".

## Risks & Open Questions

- **Query attribution to a process is the hard part** and is unavailable from
  most log sources. Without it, "a new domain was resolved" is much weaker.
  **Open:** is eBPF attribution worth the privilege and portability cost?
- **Legitimate services look like tunnels.** Some CDNs, anti-virus telemetry and
  certificate-transparency lookups use long, high-entropy, high-rate DNS. An
  allowlist will be necessary and will need maintaining.
- **Encrypted DNS defeats this entirely.** A host using DoH to a third party
  bypasses every local observation point. That is worth reporting as a posture
  finding in its own right — the module should say when it is blind.
- **Packet capture needs privilege**, and log sources vary by distribution.
  Coverage will be uneven across hosts, so the fleet view must show which hosts
  are actually observable rather than implying uniform coverage.
