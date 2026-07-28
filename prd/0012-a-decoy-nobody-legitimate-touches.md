---
openprd: "0.2"
id: "0012"
title: "A decoy nobody legitimate touches"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: honeypot, deception, decoy, high-precision, modules
supersedes:
superseded-by:
---

## Problem

Every other detection module in this product fights the same war: separating
attack from noise, and paying for it in false positives, baselines, warmup
periods and tuning. `deps` collapses overlapping rules, `secrets` suppresses
documentation keys, `sast` caps pattern-only confidence, `log-watcher`
distinguishes a `200` from a `404`.

**A honeypot inverts the problem.** A service that exists for no reason, that
nothing legitimate is configured to contact, that is not in DNS and not linked
from anywhere, has exactly one class of visitor. **Any interaction is, by
construction, unauthorized** — so a honeypot produces the highest-precision
signal available on a host, with no baseline, no warmup and no tuning.

That property is worth a lot in the context of this product:

- It gives a **near-zero-false-positive tripwire** to corroborate noisier
  detectors — directly useful to `firewall-rules` (PRD 0010), where the open
  question is whether blocking should require two signals.
- It detects **internal** attackers and post-compromise lateral movement, which
  perimeter-oriented detection misses entirely.
- It yields **attacker artefacts** — credentials tried, commands run, payloads
  uploaded — which is intelligence the other modules cannot produce.

The catch is that a honeypot is a service that deliberately invites attackers,
running on a customer's production host. If it is exploitable, the security
product becomes the entry point.

## Goals

- Any interaction with a decoy raises a **high-confidence** alert immediately,
  with no baseline required.
- Decoys capture **what the attacker tried** — credentials, commands, payloads —
  as evidence.
- The decoy is **not exploitable**: it emulates, never executes, and holds
  nothing real.
- Deploying a decoy is one command, because a tripwire nobody sets up detects
  nothing.

## Non-Goals

- **Not a research honeypot.** Cowrie and T-Pot exist for capturing malware at
  depth; this is a tripwire, not a laboratory.
- **Not a real service.** No decoy ever executes a command, serves a real file,
  or holds real data.
- **Not internet-scale deception.** One host, a handful of ports.
- **Not blocking** — it feeds `firewall-rules` (PRD 0010) and `tar-pit`
  (PRD 0013).

## Users

- **Solo operators** who want one unambiguous "someone is inside" signal.
- **Platform engineers** placing tripwires on internal segments where lateral
  movement would otherwise be invisible.
- **Incident responders** who need to know what an attacker was looking for.

## Requirements

### Serve

- R1 [P0] **SSH decoy**: complete the protocol banner and authentication
  exchange, record username, password and key fingerprint, always reject. Never
  allocate a shell, never execute anything.
- R2 [P0] **HTTP decoy**: plausible admin login pages (`/admin`, `/wp-login.php`,
  `/phpmyadmin`), recording credentials and request bodies, always failing.
- R3 [P1] **Database decoys**: MySQL/Postgres/Redis handshakes, recording the
  credentials offered.
- R4 [P0] **Emulation only.** Every decoy is a protocol emulator with no
  execution path, no filesystem access and no real backend. This is the property
  that keeps the module from becoming the vulnerability.
- R5 [P0] **Bounded resources per decoy** — connection caps, byte caps, timeouts
  — so the decoy cannot be used to exhaust the host it protects.

### Detect and report

- R6 [P0] **Any connection is an alert**, at high severity, with source, decoy,
  and what was attempted.
- R7 [P0] Capture and store credentials tried, commands attempted and payloads
  offered, size-capped and redaction-aware — captured payloads are hostile input
  and must never be executed, rendered or interpolated anywhere.
- R8 [P1] Correlate repeat sources across decoys; a source touching three decoys
  is enumerating.
- R9 [P1] Feed confirmed sources to `firewall-rules` as a high-confidence block
  candidate — the one detector whose precision genuinely justifies automated
  blocking.

### Operate

- R10 [P0] **Port selection must not collide** with real services; refuse to
  bind rather than displace something real.
- R11 [P0] Decoys are clearly identifiable **to the operator** in process and
  port listings, so a future incident responder does not mistake the decoy for a
  compromise.
- R12 [P1] `threatcrush honeypot status` showing decoys, ports and hit counts.

## UX Notes

```toml
[honeypot]
enabled = true

[[honeypot.decoys]]
type = "ssh"
port = 2222

[[honeypot.decoys]]
type = "http"
port = 8080
pages = ["/admin", "/wp-login.php"]
```

```
[HIGH] honeypot · SSH decoy contacted

  203.0.113.9 → decoy ssh :2222
  tried: root/admin123, root/P@ssw0rd, deploy/deploy   (3 attempts, 4s)

  Nothing legitimate connects to this port. Treat this source as hostile.
```

## Success Metrics

- **Zero false positives.** The defining property: any alert corresponds to a
  real unauthorized interaction. Anything else is a bug in port selection or
  documentation, not a tuning problem.
- Credentials and commands captured on 100% of fixture interactions.
- Decoys survive a fuzzing pass with no crash, no resource exhaustion and no
  execution.
- One-command deployment; decoy live in <5s.

## Risks & Open Questions

- **The decoy must never become the entry point.** This is the whole risk. It
  is why R4 makes emulation structural rather than an implementation choice, and
  why fuzz-resistance is an acceptance metric rather than a nice-to-have.
- **Captured payloads are attacker-controlled data** that will be rendered in
  alerts, dashboards and logs. Every downstream consumer must treat them as
  hostile — this is a stored-XSS or log-injection vector aimed at the defender.
- **A decoy advertises that the host is monitored**, which sophisticated
  attackers may use to change behaviour or avoid tripwires. Generally an
  acceptable trade for the precision.
- **Legal exposure of capturing credentials**, which may be real ones reused
  from elsewhere. Storage should be short-lived and hashed where the plaintext
  is not needed for triage. **Open:** should captured passwords be stored at all,
  or only their fingerprint plus length?
- **Open:** should decoys be off by default? They are the most valuable detector
  here and the only one that opens a listening port — which is exactly what
  `network-monitor` (PRD 0008) is built to flag as suspicious. The two modules
  must know about each other.
