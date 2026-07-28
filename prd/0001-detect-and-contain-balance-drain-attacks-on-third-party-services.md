---
openprd: "0.2"
id: "0001"
title: "Detect and contain balance-drain attacks on third-party services"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation:
tags: spend-guard, billing, fraud, sms-pumping, irsf, auto-recharge, containment, modules
supersedes:
superseded-by:
---

## Problem

On 2026-06-29/30 an attacker ran an SMS-pumping (IRSF) campaign against
qrypt.chat's phone-OTP signup. They enumerated number ranges they control in
Ukraine (+380), Kyrgyzstan (+996) and elsewhere, triggered 520 verification
SMS, and collected the carrier revenue share. Cost: **$172.26 in two days.**

Nobody noticed for a month.

A second, smaller wave on 2026-07-27 was noticed only because a human happened
to look at auth traffic the following day. Reconstructing it after the fact
took hours of log forensics. Total confirmed loss across three waves — plus a
probe in January 2026 on the same +380 range that also went unnoticed — is
**~$194.65, roughly 61% of the account's lifetime Twilio spend.**

Three things make this worth building a module for:

**The attack is invisible to everything ThreatCrush currently monitors.** No
port scan, no failed login, no malicious payload, no CVE. The attacker used the
public signup form exactly as designed. `network-monitor`, `ssh-guard`,
`log-watcher` and `code-scanner` are all structurally blind to it, because the
damage is financial, not technical. The loss happens at a third party the
server never talks to directly.

**The only thing that stopped it was running out of money.** Not a rate limit,
not an alert, not a human. The Twilio balance hit zero and the sends started
failing with `20003`. That is a catastrophic control to depend on — and it
**inverts completely the moment auto-recharge is enabled.** With auto-recharge
on, the balance floor that accidentally saved this account becomes an unbounded
credit line against a stored card, and the attacker's ceiling is the card limit
or the fraud department, whichever trips first. This class of attack is
strictly worse for well-configured accounts.

**The signal was unmistakable in hindsight.** Legitimate traffic cost
**$0.0079–$0.02/message**. The fraud ran **$0.29–$0.33/message** — a **~40×
unit-cost anomaly**, sustained, on a metric already exposed by the provider's
billing API. Nothing needed to be inferred; nobody was looking.

Generalizing: any metered third-party service with a stored payment method and
a public trigger is exposed — SMS/voice, transactional email, LLM inference,
object storage egress, translation, geocoding, push. The pattern is always the
same: an attacker finds an endpoint where *your* money moves on *their* input.

## Goals

- A balance-drain attack is **detected within minutes** of onset, not weeks.
- Worst-case loss for an undetected-by-human attack is **bounded and known**,
  because containment is automatic rather than advisory.
- Accounts with auto-recharge enabled are **no worse off** than accounts
  without it — the unbounded-credit-line failure mode is eliminated.
- Post-incident reconstruction is a **report, not an investigation**: what was
  spent, on what, to where, over what window, versus baseline.
- Operators learn about exposure **before** an incident, via posture checks on
  provider-side controls they forgot to enable.

## Non-Goals

- **Not a FinOps/cost-optimization tool.** Committed-use discounts, rightsizing
  and spend forecasting are out of scope. This is a security control that
  happens to read billing data.
- **Not a replacement for provider-native fraud controls.** Twilio Geo
  Permissions, AWS budget actions and SendGrid IP access management remain the
  correct primary defenses. This module *verifies they are on* and catches what
  they miss.
- **Not in-band rate limiting.** Applications should still rate-limit their own
  expensive endpoints. This module is the out-of-band backstop for when that
  logic is missing, misconfigured, or bypassed.
- **Not a general-purpose anomaly platform.** Scope is metered third-party
  spend, not arbitrary metric monitoring.
- **Not automatic dispute/chargeback filing.** Generate the evidence pack; a
  human files it.

## Users

- **Solo founders and small teams** running many small services against shared
  provider accounts, with no dedicated security or finance function. Primary
  persona — this is the qrypt.chat situation, and the one where a month can
  pass unnoticed.
- **Platform/ops engineers** who own provider credentials across an estate and
  need a uniform tripwire rather than per-provider bespoke alerting.
- **Incident responders** reconstructing what a spend anomaly cost and who it
  paid, after the fact.

## Requirements

### Connect

- R1 [P0] Provider connector interface: authenticate read-only against a
  provider's usage/billing API, normalize to a common shape
  (`timestamp, category, quantity, unit_cost, total_cost, destination,
  metadata`), and poll on an interval.
- R2 [P0] Ship connectors for **Twilio** (reference implementation — Usage
  Records Daily + Balance) and **one non-telecom provider** to prove the
  abstraction generalizes. Candidates: OpenAI/Anthropic, SendGrid, AWS.
- R3 [P1] Additional connectors: Vonage, Telnyx, Mailgun, Cloudflare, AWS
  (Cost Explorer + Budgets), Stripe.
- R4 [P1] Credentials resolve from env, file, or the existing ThreatCrush
  secret store — never inline in `mod.toml`. Read-only scope where the
  provider supports scoped keys.

### Detect

- R5 [P0] **Unit-cost anomaly.** Alert when rolling unit cost exceeds the
  learned baseline by a configurable factor. This is the highest-signal
  detector and it caught the reference incident cleanly (40× deviation,
  sustained over 48h, zero ambiguity).
- R6 [P0] **Balance burn rate and time-to-zero.** Track balance velocity;
  alert when projected time-to-zero drops below a threshold.
- R7 [P0] **Auto-recharge monitoring.** Count recharge events per rolling
  window. More than N in the window is a **critical** alert and a containment
  trigger — this is the unbounded-loss failure mode and it must be treated as
  categorically more severe than volume alone.
- R8 [P1] **Destination anomaly.** Flag spend to destinations (country codes,
  regions, endpoints) absent from the learned baseline. In the reference
  incident, +996/+959/+358 had no prior traffic whatsoever.
- R9 [P1] **Volume and velocity anomaly** against learned baseline, with
  day-of-week and hour-of-day seasonality.
- R10 [P1] **Conversion anomaly.** Optional app-supplied outcome metric
  (signups, deliveries, conversions). Spend that produces no business outcome
  is the strongest possible fraud signal — the reference incident sent 26 SMS
  and produced 0 completed accounts. Requires app integration, hence P1.
- R11 [P1] **Baseline learning** over a configurable window, with explicit
  warmup. Never alert from an unlearned baseline; never silently fold an
  ongoing attack into the baseline (quarantine anomalous windows from baseline
  updates, or the attack normalizes itself).

### Contain

- R12 [P0] **Tiered response**, per detector and severity: `alert` → `throttle`
  → `halt`. Configurable, default `alert` only, with containment strictly
  opt-in per provider.
- R13 [P0] **Kill switch.** On a `halt` trigger, execute a configured
  containment action: revoke/disable the provider API key, flip an
  application-side circuit breaker (webhook/file/env), or invoke a
  provider-specific action.
- R14 [P0] **Disable auto-recharge** as a first-class containment action where
  the provider API allows it. This is the single highest-value action
  available and directly addresses the unbounded-loss mode in R7.
- R15 [P1] **Provider-native control enforcement** where the API allows —
  e.g. tighten Twilio Geo Permissions to the learned-legitimate country set.
- R16 [P0] **Containment is reversible and logged.** Every action records what
  was changed, when, why (which detector, what values), and how to undo it.
  A dry-run mode must show exactly what *would* fire.

### Report

- R17 [P1] Incident report: window, total anomalous spend, baseline
  comparison, destination breakdown, unit-cost curve, containment timeline.
  Sufficient to open a provider fraud ticket without further forensics.
- R18 [P2] **Posture audit** (`spend-guard audit`): check provider-side
  controls independent of any attack — geo permissions scoped? auto-recharge
  capped? spend alerts configured? API keys scoped and rotated? Surfaces
  exposure before it costs anything.
- R19 [P2] Cross-provider dashboard in the existing TUI/desktop apps.

## UX Notes

Ships as a core module, `spend-guard`, following the existing module contract
(`mod.toml`, config in `threatcrushd.conf.d/spend-guard.conf`, alerts routed
through `alert-system` so Slack/Discord/email/PagerDuty come free).

```bash
threatcrush modules install spend-guard
threatcrush spend-guard providers add twilio --from-env
threatcrush spend-guard status          # balances, burn rate, time-to-zero
threatcrush spend-guard baseline        # learned normals per provider
threatcrush spend-guard audit           # provider-side posture check
threatcrush spend-guard test --simulate 40x-unit-cost   # dry-run the rules
threatcrush spend-guard report --since 2026-06-28       # incident pack
```

Config sketch:

```toml
[providers.twilio]
enabled = true
credentials = "env:TWILIO_ACCOUNT_SID,env:TWILIO_AUTH_TOKEN"
poll_interval = "5m"

[providers.twilio.detect]
unit_cost_factor   = 5.0      # 40x observed in the reference incident
burn_rate_usd_hour = 10.0
time_to_zero       = "6h"
autorecharge_max   = 2        # per 24h
new_destination    = "alert"

[providers.twilio.respond]
unit_cost_factor   = "halt"   # revoke key + disable auto-recharge
burn_rate_usd_hour = "alert"
autorecharge_max   = "halt"

[providers.twilio.contain]
disable_autorecharge = true
revoke_api_key       = true
circuit_breaker      = "webhook:https://qrypt.chat/api/internal/sms-breaker"
```

Alerts must lead with money and evidence, not metric names — the operator's
first question is always "how much, and is it still happening":

```
[CRITICAL] spend-guard · twilio · UNIT COST 41x BASELINE
  Baseline $0.0079/msg → now $0.3291/msg  (533 msgs, 48h)
  Spend: $175.42 (baseline $1.48/mo)   Balance: $17.93 → zero in ~1h
  New destinations: +380 (184 nums), +996 (171 nums)
  ACTION TAKEN: auto-recharge disabled, API key revoked, breaker tripped
  Undo: threatcrush spend-guard undo 4a91c
```

Design constraints:

- **Alert once per incident, not per poll.** A drain lasting 48h must not
  generate 576 alerts. Deduplicate on incident identity; escalate on severity
  change, not on repetition.
- **Never require an operator to compute anything.** Show the baseline, the
  current value, the multiple, and the dollar total together.
- **Containment must be undoable from the alert itself.** A false positive
  that halts signups at 3am needs a one-command reversal.

## Success Metrics

- **Time to detect** < 5 minutes from attack onset (vs. ~30 days for the
  reference incident's largest wave).
- **Time to contain** < 1 minute after detection, unattended.
- **Bounded loss:** worst-case undetected-by-human spend < $25 at default
  config, against $172.26 actual in the reference incident — a ≥85% reduction.
- **Replay accuracy:** the June 29–30 and July 24/27 waves, replayed from real
  Twilio usage data, are each detected with correct severity; the legitimate
  October 2025 international traffic ($0.1844/msg — elevated, but real users)
  does **not** alert. This asymmetric case is the key acceptance test: the
  detector must separate expensive-but-legitimate from expensive-and-fraudulent.
- **False positive rate** < 1 per provider per month at default thresholds.
- **Posture audit** surfaces ≥1 real misconfiguration on first run against an
  existing account.

## Risks & Open Questions

- **Credential scope is the core tension.** Containment (R13–R15) requires
  write-capable credentials, which makes the ThreatCrush host a higher-value
  target — a compromised agent could revoke every provider key in the estate.
  Mitigation: containment credentials stored separately from read credentials,
  opt-in per provider, default read-only. **Open:** should containment run via
  a separate least-privilege credential the module cannot read at poll time?
- **Billing API lag caps detection speed.** Twilio Usage Records are not
  real-time; some providers report hourly or daily. Detection latency is
  bounded below by provider lag, which may make the <5min goal unreachable for
  some. **Open:** supplement with faster proxies — message-level APIs, balance
  deltas, provider webhooks — where available? Per-provider realistic latency
  targets need documenting rather than one global number.
- **Containment blast radius.** Revoking an API key stops the attack and also
  stops legitimate signups. For a consumer app, an unnecessary halt may cost
  more in lost users than the fraud it prevents. Default must stay `alert`;
  `halt` is an explicit operator decision per provider.
- **Legitimate growth resembles an attack.** A launch, a viral moment, or
  genuine expansion into a new country all look like volume + destination
  anomalies. Unit cost and conversion rate are the discriminators — real users
  in Nigeria still convert; +996 pumping does not. **Open:** should `halt` be
  gated on ≥2 concurrent detectors to reduce false-positive blast radius?
- **Baseline poisoning.** A slow-ramp attacker could raise the baseline
  gradually until the drain looks normal. Needs absolute ceilings alongside
  relative thresholds, and anomalous windows must be excluded from baseline
  updates.
- **Provider API coverage is uneven.** Disabling auto-recharge (R14) may not be
  API-accessible everywhere; where it isn't, the module can only alert. **Open:**
  document per-provider capability honestly in a support matrix rather than
  implying uniform protection.
- **Open:** is `spend-guard` a core module (bundled, per PRD.md's core list) or
  a paid marketplace module? It carries real, quantifiable dollar value, which
  argues for paid — but the failure mode it prevents is severe enough that
  bundling it may serve users better.
