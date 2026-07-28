---
openprd: "0.2"
id: "0014"
title: "Learn about a breach when the stolen credential is used"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: deception, canary-tokens, breach-detection, dwell-time, modules
supersedes:
superseded-by:
---

## Problem

`PRD.md` describes this module as "serves fake /etc/passwd, fake DB dumps, fake
API keys to attackers". Serving fake data to someone already reading your files
is of limited value on its own — they have already won by then. **The valuable
version of the same idea is the canary token: a fake credential planted where
only an intruder would find it, which alerts the moment somebody tries to use
it.**

That inversion matters because of what it detects and when:

- **It detects the breach you missed.** Every other module in this product
  tries to catch the intrusion as it happens. A canary catches it *afterwards*
  — when the attacker, having already got in undetected, starts using what they
  took. That is the case where dwell time runs to months.
- **It has no false positives by construction**, for the same reason a honeypot
  does not: nothing legitimate ever uses a credential that was never issued to
  anything.
- **It detects theft at rest**: a leaked backup, a stolen laptop, an
  over-permissive S3 bucket. The token fires wherever it ends up, not only on
  the host it was planted on.

The honest constraint is that a canary only fires when the attacker *uses* it,
which means the module reports facts about the past. It should say so rather
than implying real-time protection.

## Goals

- **Use** of a planted credential raises an immediate, unambiguous alert.
- Tokens are **indistinguishable from real credentials** to an attacker
  inspecting them.
- Planting a token is one command, in the places attackers actually look.
- Detects theft that occurred **before** ThreatCrush was installed, provided a
  token was reachable.

## Non-Goals

- **Not a replacement for real detection.** A canary tells you afterwards. Every
  other module tries to tell you during.
- **Not honeypot services** — that is `honeypot` (PRD 0012). This is data, not
  listeners.
- **Not offensive.** Tokens identify their use; they do not attack, deanonymize
  beyond connection metadata, or execute anything on the user's machine.
- **Not a hosted canary service.** Where a token requires a callback endpoint,
  integrate with an existing provider or the operator's own; running that
  infrastructure is a separate product.

## Users

- **Solo operators** who would otherwise never learn a backup was taken.
- **Platform engineers** seeding tokens across a fleet as a breach tripwire.
- **Incident responders** proving that specific data was exfiltrated, and when.

## Requirements

### Plant

- R1 [P0] **Token types**: AWS-shaped key pairs, database connection strings,
  API keys with a plausible provider prefix, and a document containing a
  callback URL.
- R2 [P0] **Placement in believable locations**: `.env.backup`, `credentials`,
  `config/secrets.yml`, a `dump.sql` — the same places `code-scanner`'s
  `secrets` subsystem looks, which is not a coincidence.
- R3 [P0] **Realism.** A token must survive inspection: correct prefix, correct
  length, correct character set, and a checksum where the format defines one.
  An obviously-fake key is ignored and the tripwire is wasted.
- R4 [P0] **The planted files must be excluded from this product's own
  scanners**, or `code-scanner` reports the decoys as findings and the operator
  learns to ignore credential alerts — the worst possible outcome.

### Detect

- R5 [P0] **Use detection** by the mechanism appropriate to the type: AWS
  CloudTrail for key use, a callback for URL tokens, a login attempt for
  database credentials.
- R6 [P0] **Alert with context**: which token, where it was planted, when, and
  everything known about the use — source address, user agent, service.
- R7 [P1] **Inventory and rotation**: list every planted token, where it lives,
  and its status; regenerate on demand.
- R8 [P1] Correlate with `honeypot` (PRD 0012) and `log-watcher` (PRD 0009):
  a token used shortly after an anomaly ties the two together.

### Report

- R9 [P0] **Critical severity, always.** Token use has no benign explanation.
  This is the one alert in the product that should never be summarized,
  digested, or subject to quiet hours.
- R10 [P0] The alert must state plainly that **the credential was already
  stolen** — the finding is a past breach, not a present attempt.

## UX Notes

```bash
threatcrush deception plant --type aws --path /srv/app/.env.backup
threatcrush deception list
threatcrush deception rotate <id>
```

```
[CRITICAL] deception · canary credential used

  token: aws-key-4a91c   planted 2026-05-02 in /srv/app/.env.backup
  used:  2026-07-28T14:11Z from 198.51.100.22 (AS64512)
  call:  sts:GetCallerIdentity

  This credential was never valid for anything. Its use means the file it was
  planted in was read and exfiltrated — at some point since 2026-05-02.

  Now: treat every other credential in that file as compromised and rotate it.
```

## Success Metrics

- **Zero false positives.** Structural, as with `honeypot`.
- Token use alerts within 60s of the triggering event, where the detection
  mechanism allows.
- Realism: planted tokens pass format validation for their claimed provider,
  including checksums.
- **This product's own scanners never report a planted token** — asserted by
  test, because the failure mode teaches operators to dismiss real credential
  alerts.
- Alert clearly conveys that data was already taken, not that an attempt was
  blocked.

## Risks & Open Questions

- **A canary in the wrong place is a real credential to a confused colleague.**
  Someone may find a planted key and spend an afternoon on why it does not work.
  Inventory (R7) and clear internal documentation are the mitigation.
- **Tokens requiring a callback create an external dependency** and leak the
  fact of an alert to whoever hosts it. **Open:** self-hosted callback endpoint
  as a first-class option?
- **AWS-shaped tokens require a real AWS account** to observe use through
  CloudTrail. Without one, that token type cannot fire — a coverage gap that
  must be stated rather than implied.
- **The interaction with `code-scanner` is a genuine design hazard** and R4 is
  not optional: two of this product's modules must not fight each other, and the
  one that loses is credibility.
- **Open:** should tokens be planted automatically during `threatcrush init`?
  It maximizes coverage and plants credential-shaped files on a customer's disk
  without them thinking hard about it. Probably opt-in, prominently offered.
