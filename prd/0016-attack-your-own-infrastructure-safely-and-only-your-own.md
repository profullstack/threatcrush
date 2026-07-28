---
openprd: "0.2"
id: "0016"
title: "Attack your own infrastructure, safely, and only your own"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: pentest-engine, authorization, blast-radius, dast, scanning, modules
supersedes:
superseded-by:
---

## Problem

Every other module in this product **observes**. This one **acts on a target**,
and that single difference makes authorization and blast radius the whole
design problem rather than a section of it.

The value is straightforward: a running application has vulnerabilities that no
amount of source analysis will reveal, because they emerge from configuration,
routing, middleware order and framework behaviour rather than from code.
`code-scanner`'s `sast` subsystem (PRD 0004) is explicitly pattern-level and
says so; testing the live endpoint is how you find what it cannot.

Three hazards dominate:

**Testing something you do not own.** A misconfigured target, a typo'd
hostname, a shared IP, a CDN or a stale DNS record pointed at someone else's
infrastructure — and the operator has run an unauthorized attack against a third
party. That is a legal problem, not a bug.

**Breaking the thing you are testing.** Fuzzing an endpoint can create records,
send emails, charge cards, exhaust rate limits, corrupt data or take a
production service down. A security tool that causes the outage has failed
completely.

**Findings nobody can trust.** A DAST tool that reports probable issues without
reproducible evidence generates work rather than value.

## Goals

- Vulnerabilities that only appear at runtime are found against the operator's
  own applications.
- **Testing an unauthorized target is structurally difficult**, not merely
  discouraged.
- Destructive potential is **bounded and opt-in**; the default profile cannot
  reasonably break a production application.
- Every finding is **reproducible**, with the exact request that demonstrates it.

## Non-Goals

- **Not a full DAST suite.** Burp and ZAP exist. This covers common classes
  against the operator's own endpoints.
- **Not exploitation.** Prove a vulnerability exists; never establish a
  foothold, pivot or extract more data than proves the point.
- **Not testing third parties**, at any scale, under any configuration.
- **Not continuous by default.** Active testing is a scheduled, deliberate act.

## Users

- **Solo founders** who have never had an application tested and will not buy a
  pentest.
- **Platform engineers** wanting a pre-deploy check against staging.
- **Developers** validating that a fix actually closed the hole.

## Requirements

### Authorization — the gate everything passes through

- R1 [P0] **Explicit target allowlist.** No target is testable until it is
  listed in configuration. There is no "scan whatever you find" mode, and
  discovery never feeds the scanner directly.
- R2 [P0] **Ownership verification** before any active test: a DNS TXT record, a
  file served at a well-known path, or the target resolving to an interface on
  the local host. Verification is re-checked before each run, since DNS moves.
- R3 [P0] **Refuse to test** any target that fails verification, resolves to a
  shared CDN address, or is a cloud metadata endpoint — no override flag.
- R4 [P0] **Every run is logged locally with its authorization evidence**, so
  the operator can demonstrate what was authorized and when.

### Bounded testing

- R5 [P0] **Safety profiles**, defaulting to the safest: `passive` (observe
  responses, no mutation), `safe` (non-destructive probes only), `aggressive`
  (fuzzing and mutation, explicit opt-in, never the default).
- R6 [P0] **Never send destructive HTTP methods** or payloads designed to write,
  delete or send, outside `aggressive`.
- R7 [P0] **Rate limiting and a global request budget**, so a test cannot
  degrade the service being tested.
- R8 [P0] **Immediate abort** if the target starts returning `5xx` above a
  threshold — the tool must notice it is causing harm and stop.
- R9 [P1] Scheduled runs restricted to configured windows.

### Test classes

- R10 [P0] Reflected XSS, SQL injection, path traversal, open redirect,
  authentication bypass on obvious paths, and security-header/TLS posture.
- R11 [P1] SSRF, IDOR against declared object patterns, CORS misconfiguration.
- R12 [P2] API fuzzing from an OpenAPI schema, which bounds it far better than
  blind fuzzing.

### Report

- R13 [P0] **Every finding includes the exact reproducing request** — method,
  path, headers, body — and the response evidence.
- R14 [P0] Confidence stated as in PRD 0004: `confirmed` (the payload
  demonstrably worked) versus `suspected`.
- R15 [P1] Retest a single finding, so a fix can be verified in one command.

## UX Notes

```toml
[pentest-engine]
enabled = true
profile = "safe"                 # passive | safe | aggressive
max_requests_per_run = 5000
requests_per_second = 5
abort_on_error_rate = 0.2

[[pentest-engine.targets]]
url = "https://app.example.com"
verification = "dns-txt"         # threatcrush-verify=<token>
```

```bash
threatcrush pentest verify https://app.example.com   # prove ownership first
threatcrush pentest https://app.example.com
threatcrush pentest retest <finding-id>
```

Design constraint: **`verify` is a separate, mandatory step.** Making
authorization its own command, with its own output, means nobody arrives at a
scan without having consciously claimed the target.

## Success Metrics

- **Zero unauthorized targets tested.** Asserted by test: unverified targets,
  CDN-shared addresses and metadata endpoints are refused with no override.
- Zero production incidents caused by a `safe`-profile run.
- 100% of findings reproduce from the request recorded in the report.
- Abort triggers within 10 requests of the error-rate threshold being crossed.
- Detection of one deliberate instance of every P0 class in a fixture app.

## Risks & Open Questions

- **Testing the wrong target is the risk that could end the product.** R1–R4 are
  the mitigations and deliberately admit no override flag; an override would be
  used exactly once, by someone in a hurry, against someone else's server.
- **Even a `safe` profile can cause harm.** A GET to an endpoint with side
  effects, a login attempt that triggers lockout, a probe that fills a log disk.
  Rate limiting and abort help; the residual risk is real and should be stated
  in the documentation rather than glossed.
- **Ownership verification is not the same as authorization.** Controlling DNS
  for a domain does not always mean permission to test the application on it —
  shared hosting and managed platforms have terms of their own. **Open:** should
  the opt-in text require the operator to affirm they have permission, not just
  control?
- **This module is an attack tool on a customer's server.** If ThreatCrush is
  compromised, it is a ready-made weapon with credentials and a target list.
  That argues for keeping it off by default and separating its configuration
  from the daemon's general config.
- **Open:** should `aggressive` be restricted to targets explicitly marked
  non-production, refusing to run against anything the operator has not labelled
  as staging?
