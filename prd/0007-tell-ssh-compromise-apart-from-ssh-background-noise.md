---
openprd: "0.2"
id: "0007"
title: "Tell SSH compromise apart from SSH background noise"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: ssh-guard, brute-force, authentication, tunneling, posture, modules
supersedes:
superseded-by:
---

## Problem

Any internet-facing SSH port receives thousands of failed logins a day from
commodity botnets. That is **weather, not an attack** — and treating it as an
attack is why most SSH monitoring produces noise nobody reads.

The events that actually matter are rare and different in kind:

- a login that **succeeds** from somewhere or someone unusual,
- a **new authorized key** appearing in an `authorized_keys` file,
- **port forwarding or tunneling** established by a session, which is how a
  foothold becomes lateral movement,
- a successful login **after** a burst of failures — the one case where the
  noise was the prelude.

**fail2ban already blocks brute force, and blocking is the least valuable
half.** Distributed botnets rotate IPs faster than a ban list matters, and a ban
list is whack-a-mole. The valuable half is knowing that someone got *in*, and
what they did in the first sixty seconds.

**The deepest finding is usually posture, not an event.** A host still
accepting password authentication, permitting root login, or carrying an
`authorized_keys` entry nobody recognizes is exposed continuously, not
occasionally. That should be reported once, clearly, rather than waiting for
the event it eventually causes.

## Goals

- A **successful** authentication that is unusual for this host is surfaced
  within seconds, with what made it unusual.
- Failed-login floods are **summarized, not enumerated** — a count and a
  pattern, never one alert per attempt.
- A change to `authorized_keys` is treated as a **critical** event, because it
  is the standard persistence mechanism.
- Weak SSH posture is reported **before** it is exploited.
- Distinguish "we are being scanned like everyone else" from "something
  happened here".

## Non-Goals

- **Not a replacement for fail2ban**; `firewall-rules` (PRD 0010) owns blocking.
  This module detects and explains.
- **Not an SSH proxy or bastion.** Nothing sits in the connection path.
- **Not session recording.** Capturing keystrokes on a production host is a
  privacy decision no monitoring agent should make by default.

## Users

- **Solo operators** whose VPS has SSH open and who have never read
  `/var/log/auth.log`.
- **Platform engineers** verifying that key rotation actually happened.
- **Incident responders** reconstructing how and when access was obtained.

## Requirements

### Observe

- R1 [P0] Parse SSH authentication events from journald and `auth.log`/`secure`,
  tolerating both OpenSSH log formats.
- R2 [P0] Extract: outcome, method (password/publickey), user, source IP, key
  fingerprint where present, and timestamp.

### Detect

- R3 [P0] **Successful login anomaly** — first-ever source IP or ASN for this
  account, a first-time key fingerprint, or an unusual hour relative to the
  learned baseline.
- R4 [P0] **Success after failure burst** from the same source or subnet. The
  single highest-signal sequence in SSH logs.
- R5 [P0] **`authorized_keys` change** on any account, reported with the key
  comment and fingerprint. Critical by default.
- R6 [P1] **Brute-force summarization**: one incident per (source, window) with
  counts, not one alert per attempt.
- R7 [P1] **Tunneling and forwarding** established by a session, which converts
  a single compromised account into network access.
- R8 [P1] **Root login success**, always notable regardless of baseline.
- R9 [P1] **Posture audit**: `PasswordAuthentication`, `PermitRootLogin`,
  key algorithms, unknown `authorized_keys` entries, `AllowUsers` scope.

### Report

- R10 [P0] Alerts route through `alert-system` (PRD 0006), with brute-force
  noise at a low severity and successful-access anomalies high.
- R11 [P1] Baseline learning with explicit warmup; never alert from an unlearned
  baseline, and never fold an ongoing compromise into the baseline.

## UX Notes

```toml
[ssh-guard]
enabled = true
sources = ["journald", "/var/log/auth.log"]
baseline_days = 14
alert_on_new_source_ip = true
authorized_keys_watch = true
brute_force_summary_window = "15m"
```

```
[CRITICAL] ssh-guard · successful login after 1,847 failures

  user: deploy   from: 203.0.113.44 (AS12345, first seen)
  method: password   at 03:14 UTC

  1,847 failures from this /24 in the preceding 20 minutes, then success.
  Password auth is enabled on this host.

  Now: check `last`, check authorized_keys, rotate the account's credentials.
```

Design constraints:

- **Never one alert per failed login.** The summary is the alert.
- **Say what to do in the first minute.** A successful-compromise alert should
  not require the operator to remember the runbook at 3am.

## Success Metrics

- Zero alerts from ordinary botnet failure traffic at default settings; one
  low-severity summary per source per window.
- 100% detection on a fixture set: success-after-burst, new-key addition, root
  login, forwarding request.
- Successful-login anomaly precision ≥80% after warmup on a real host.
- Posture audit surfaces ≥1 genuine weakness on first run against a typical VPS.

## Risks & Open Questions

- **Legitimate access is genuinely irregular.** Operators travel, ISPs rotate
  addresses, CI deploys from new runners. A first-seen-IP rule alone will cry
  wolf; it needs the baseline and ideally a second signal.
- **Baseline poisoning**: an attacker with persistent access becomes "normal".
  Anomalous windows must be excluded from baseline updates, as in PRD 0001.
- **`authorized_keys` changes are also routine** during legitimate onboarding.
  Critical severity is right, but it needs a low-friction acknowledgement path
  or it will be muted.
- **Open:** should this module read `sshd_config` (posture) at all, or does that
  belong in `code-scanner`'s `config` subsystem (PRD 0005)? The check is
  configuration; the context is SSH. Duplicating it in both is the wrong answer.
