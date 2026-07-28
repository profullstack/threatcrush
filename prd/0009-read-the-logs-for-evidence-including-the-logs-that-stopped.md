---
openprd: "0.2"
id: "0009"
title: "Read the logs for evidence, including the logs that stopped"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: log-watcher, logs, web-attacks, tampering, gaps, modules
supersedes:
superseded-by:
---

## Problem

Logs are where the evidence of an intrusion already is. The difficulty is that
a busy web server writes millions of lines a day, almost all of it either
routine traffic or automated probing, and a tool that surfaces every `404` on
`/wp-admin` produces exactly the output nobody reads.

Three classes of finding are worth an operator's attention:

**Attacks that succeeded.** A traversal attempt returning `404` is noise; the
same request returning `200` is an incident. **Status code is the difference
between a probe and a breach**, and it is the discriminator most log tooling
underuses.

**Log gaps and tampering.** A log that stops mid-day, shrinks, or loses its
inode while the service is still running is a strong signal in itself —
clearing traces is standard post-exploitation, and it is invisible to anything
that only pattern-matches log *contents*. **A missing log is evidence.**

**Application-level errors that indicate probing at depth**: sudden spikes in
`500`s from one source, authentication errors against many accounts, or bursts
of unusual user agents against endpoints that are normally quiet.

## Goals

- A **successful** exploitation attempt visible in web logs is surfaced within
  one interval, distinguished from the probing that surrounds it.
- **Log discontinuity is itself an alert** — truncation, rotation anomalies, a
  service still running while its log went silent.
- Routine probing is **summarized as weather**, not enumerated.
- Multi-format support without the operator writing regexes: nginx, Apache,
  journald, and common JSON application logs.

## Non-Goals

- **Not log shipping or centralized storage.** Loki/ELK own that; this reads
  locally and alerts.
- **Not a SIEM.** No cross-host correlation, no retention guarantees.
- **Not a WAF.** Detection after the fact, never inline blocking —
  `firewall-rules` (PRD 0010) and `tar-pit` (PRD 0013) act.
- **Not arbitrary log analytics.** Business metrics are somebody else's product.

## Users

- **Solo operators** whose nginx logs have never been read by anyone.
- **Platform engineers** who need to know when a log stopped.
- **Incident responders** who need the request that worked, not the thousand
  that failed.

## Requirements

### Read

- R1 [P0] **Tail with rotation handling** — follow by inode, detect truncation
  and re-creation, resume from a persisted offset across daemon restarts.
- R2 [P0] **Format detection**: nginx combined, Apache common/combined,
  journald, and JSON lines with configurable field mapping.
- R3 [P0] **Backpressure safety.** A log burst must never exhaust memory or
  starve the daemon; sample and report sampling rather than fall behind
  silently.

### Detect

- R4 [P0] **Attack signatures with outcome**: path traversal, SQL injection,
  command injection, template injection, scanner user-agents — each classified
  by response status, so `200`/`500` on an attack path outranks `404`.
- R5 [P0] **Log gap detection**: a log that stops while its service runs,
  shrinks, or is replaced. High severity, because it is both a failure and a
  tampering signal.
- R6 [P1] **Rate anomalies** per source and per endpoint against a learned
  baseline, with day-of-week and hour seasonality.
- R7 [P1] **Authentication failure patterns** in application logs — one account
  from many sources (credential stuffing) versus many accounts from one source
  (spraying). These are different attacks and should read differently.
- R8 [P1] **Error spikes** (`5xx`) as a probing signal, since successful
  exploitation frequently produces errors first.
- R9 [P2] Custom patterns, with the same severity and dedupe machinery.

### Report

- R10 [P0] Route through `alert-system` (PRD 0006); summarize probing at low
  severity, alert individually on successful-looking attacks.
- R11 [P0] **Include the raw request line** for a successful attack. This is the
  one place where the evidence must be quoted verbatim — unlike `secrets`, where
  quoting is the leak.

## UX Notes

```toml
[log-watcher]
enabled = true
paths = ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]
journald_units = ["nginx", "app"]
gap_alert_after = "15m"
probe_summary_window = "10m"
```

```
[CRITICAL] log-watcher · path traversal returned 200

  GET /files?path=../../../../etc/passwd  →  200  (4.1 KB)
  from 203.0.113.9  ·  curl/8.4.0  ·  2026-07-28T14:02:11Z

  1,204 similar attempts in the last hour returned 404. This one did not.

  Now: assume the file was read. Check what else that endpoint can reach.
```

Design constraint: **the 200 is the story.** Everything about the presentation
should make the difference between this line and the surrounding noise obvious
at a glance.

## Success Metrics

- Successful-attack detection: 100% on a fixture log containing traversal, SQLi
  and command injection at both `404` and `200`, with only the `200`s alerting
  individually.
- Log gap detected within the configured window on a fixture where a log is
  truncated while its unit runs.
- Zero individual alerts from 10,000 lines of ordinary scanner noise; one
  summary.
- Sustained 50k lines/minute without falling behind or growing memory.

## Risks & Open Questions

- **Status code is a good discriminator, not a perfect one.** Applications
  return `200` with an error body, and some return `500` on blocked attacks. The
  heuristic will be wrong in both directions; it is still the best cheap signal
  available.
- **Log gaps have boring causes** — rotation, disk full, a service restart.
  Alerting on all of them trains dismissal; correlating with service state
  (PRD 0008's process view) would improve this and adds a dependency.
- **Quoting request lines can capture personal data**, including session tokens
  in query strings. Necessary for triage, but it means alert channels may carry
  PII. **Open:** should query strings be redacted by default, with an opt-in to
  show them?
- **Open:** the overlap with `network-monitor` on rate anomalies is real. One
  sees connections, the other sees requests. They should not both alert on the
  same burst.
