---
openprd: "0.2"
id: "0008"
title: "Notice what changed on the network, not everything on it"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: network-monitor, listeners, egress, port-scan, baseline, modules
supersedes:
superseded-by:
---

## Problem

"Watches all TCP/UDP traffic on all ports" is how `PRD.md` describes this
module, and taken literally it produces a firehose nobody reads. Inbound port
scans are constant background radiation on any public IP; alerting on them is
alerting on the weather.

**The high-signal facts are about change, not volume:**

- **A new listening port appeared.** This is the single most valuable network
  fact on a server. A process that was not accepting connections yesterday and
  is today is either a deploy the operator knows about, or a backdoor.
- **A new outbound destination appeared**, especially from a process that has no
  business making connections. Exfiltration and C2 both look like this, and
  PRD 0002's install-script correlation depends on exactly this signal.
- **A listener's owning process changed** — same port, different binary.

**Ports bound to `0.0.0.0` that should be on loopback** are the other recurring
finding: a Postgres or Redis reachable from the internet because the default
was never changed. That is a posture fact, available instantly, and it is how a
large share of small-team data loss happens.

## Goals

- A **new listening socket** is reported within one interval, with the process,
  binary path and user that owns it.
- A **service exposed to the world that should not be** is reported as posture,
  before anything exploits it.
- Inbound scanning is **summarized as weather**, never enumerated.
- Anomalous **outbound** connections are surfaced, since that is where
  compromise becomes loss.
- The module works without packet capture, so it can run unprivileged where
  necessary and degrade honestly where it cannot.

## Non-Goals

- **Not an IDS/IPS.** Signature-matching packet inspection is Suricata's job.
- **Not full packet capture.** Storing traffic on a customer's host is a
  liability and a privacy problem.
- **Not blocking** — `firewall-rules` (PRD 0010) owns enforcement.
- **Not netflow collection** for analytics.

## Users

- **Solo operators** who do not know what is listening on their own server.
- **Platform engineers** verifying that a fleet exposes only what it should.
- **Incident responders** answering "what was it talking to?".

## Requirements

### Observe

- R1 [P0] **Socket inventory** from `/proc/net/{tcp,tcp6,udp,udp6}` plus
  `/proc/*/fd`, giving port, state, bind address, pid, process name, binary
  path and user. No elevated capture required.
- R2 [P1] **Connection sampling** for established outbound connections, with
  remote address and owning process.
- R3 [P1] **Optional packet-level features** (SYN flood detection, scan
  fingerprinting) behind an explicit capability, degrading honestly when
  unavailable rather than silently doing less.

### Detect

- R4 [P0] **New listener** relative to the learned baseline — port, process,
  binary. Critical when the binary is in a temp directory or the process is
  unnamed.
- R5 [P0] **Listener bound to all interfaces** for services that are almost
  always meant to be local: databases, caches, message brokers, admin ports.
- R6 [P0] **Listener whose owning binary changed** for a known port.
- R7 [P1] **New outbound destination** for a process, against its baseline; and
  **any** outbound connection from a process that has never made one.
- R8 [P1] **Inbound scan summarization**: one incident per source per window,
  with port count and spread, at low severity.
- R9 [P2] SYN flood and connection-rate anomalies, where capture is available.

### Report

- R10 [P0] Route through `alert-system` (PRD 0006). Scans low, new listeners
  high, world-exposed databases critical.
- R11 [P0] **State what could not be observed.** If `/proc` inspection is
  restricted or capture is unavailable, say so — a quiet module must not be
  mistaken for a quiet network.

## UX Notes

```bash
threatcrush network-monitor listeners     # what is listening, and who owns it
threatcrush network-monitor baseline
threatcrush network-monitor egress        # outbound destinations by process
```

```
[CRITICAL] network-monitor · database exposed to the internet

  0.0.0.0:5432  postgres (pid 812, /usr/lib/postgresql/16/bin/postgres)
  reachable from any address; no firewall rule restricting it

  Fix: bind to 127.0.0.1 in postgresql.conf, or restrict with firewall-rules.
       Then check the logs for connections you cannot account for.
```

## Success Metrics

- New listener detected within one interval, on a fixture that opens a port.
- Zero alerts from ordinary inbound scanning at defaults, beyond one
  low-severity summary per source.
- World-exposed database detection: 100% on a fixture host.
- Baseline warmup prevents alerting on every existing listener at install —
  the first run must not be a wall of "new" listeners.

## Risks & Open Questions

- **Deploys look exactly like backdoors.** Every legitimate release opens new
  listeners. Without a deploy signal this module will alert on normal
  operations — the same problem PRD 0002 R14 has with dependency drift, and it
  should share whatever answer that gets.
- **`/proc` inspection needs privilege** to attribute sockets to processes owned
  by other users. Running unprivileged yields ports without owners, which is
  much less useful; the degradation must be stated, not hidden.
- **Egress baselining is noisy for anything that talks to the internet** —
  package managers, telemetry, CDNs. Likely needs an allowlist of known-good
  destinations to be usable.
- **Open:** is packet capture worth the complexity and privilege at all, given
  the socket-inventory approach delivers most of the value? Deferring it keeps
  the module unprivileged, which is a real product advantage.
