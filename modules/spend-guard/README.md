# spend-guard

**Free · MIT · open source.** A ThreatCrush module that detects balance-drain
attacks on metered third-party services — SMS pumping, toll fraud, and runaway
API spend.

Implements [PRD 0001](../../prd/0001-detect-and-contain-balance-drain-attacks-on-third-party-services.md).

---

## Why this exists

An attacker ran an SMS-pumping (IRSF) campaign against a production signup form.
They enumerated phone-number ranges they control, triggered verification SMS,
and collected the carrier revenue share. **~$194 across three waves — 61% of the
account's lifetime spend on that provider. The largest wave ran for two days and
went unnoticed for a month.**

Nothing in a conventional security stack could see it:

- No port scan, no failed login, no malicious payload, no CVE.
- The attacker used the public signup form **exactly as designed**.
- The loss landed at a third party the server never talks to.

And the only thing that stopped it was **running out of money**. The balance hit
zero and sends started failing. That is a catastrophic control to depend on, and
it **inverts entirely when auto-recharge is enabled** — the floor that
accidentally saved that account becomes an unbounded draw against a stored card.
This class of attack is strictly worse for better-configured accounts.

The signal, meanwhile, was sitting in the provider's own billing API the whole
time. Legitimate traffic cost **$0.0079–$0.02/message**. The fraud cost
**$0.29–$0.33**. Nobody was looking.

## The hard part

Spotting expensive traffic is easy. Telling **expensive-and-fraudulent** from
**expensive-and-legitimate** is the actual problem.

On the same account, October 2025 averaged **$0.1844/msg** — nearly 9× the
domestic baseline — from entirely real users on Indian, Nigerian and Sri Lankan
numbers. A naive unit-cost threshold either misses the fraud or blocks a real
market.

What separates them is **shape**, not price:

|                  | Legitimate international growth | Pumping run                    |
| ---------------- | ------------------------------- | ------------------------------ |
| Unit cost        | elevated                        | elevated                       |
| Daily volume     | normal                          | **10–140× baseline**           |
| Destinations     | already seen                    | **no history**                 |
| Arrival          | spread over weeks               | **hours**                      |

So detectors are scored independently and **containment requires agreement**. A
lone elevated unit cost is an alert. Two or more signals is an incident.

`src/__tests__/detectors.test.ts` pins this down against the real numbers: it
must fire on June 29–30 and **stay quiet on October 2025**.

## Detectors

| Detector          | Fires when                                            |
| ----------------- | ----------------------------------------------------- |
| `unit_cost`       | cost/unit exceeds baseline by `unit_cost_factor`      |
| `volume`          | daily units exceed baseline by `volume_factor`        |
| `new_destination` | spend to a destination with no history                |
| `burn_rate`       | balance projected to hit zero within `burn_rate_warn_hours` |

`burn_rate` escalates to **critical** when `auto_recharge_enabled = true`,
because that is the unbounded-loss mode.

## Install

```bash
threatcrush modules install spend-guard
```

Then configure `/etc/threatcrush/threatcrushd.conf.d/spend-guard.conf` —
see [`config/example.conf.toml`](./config/example.conf.toml).

```toml
enabled = true
twilio_account_sid = "${TWILIO_ACCOUNT_SID}"
twilio_auth_token  = "${TWILIO_AUTH_TOKEN}"
auto_recharge_enabled = false
```

Use **read-only** credentials. spend-guard never needs write access to detect.

## What this does not do

Being explicit, because the gap matters:

- **It does not revoke provider API keys or disable auto-recharge.** Both are
  P0 in the PRD and both need write-scoped credentials, which would make the
  agent host a high-value target — a compromised daemon could revoke an
  estate's worth of keys. The credential-isolation design is an open question;
  shipping the write path before settling it would be irresponsible.
  Containment here is a webhook your app owns.
- **It does not replace provider-native controls.** Twilio Geo Permissions, AWS
  budget actions, SendGrid IP access management remain the primary defense.
  Blocking a destination *prevents* spend; detection only *bounds* it.
- **It cannot beat provider reporting lag.** Detection latency is bounded below
  by how fast the billing API reflects reality — minutes for some providers,
  up to a day for others.
- **It does not yet use conversion data.** Spend that produces no signups is
  the strongest fraud signal available (the reference incident sent 26 messages
  and produced 0 completed accounts), but it needs app integration.

## Providers

| Provider | Status                                                        |
| -------- | ------------------------------------------------------------- |
| Twilio   | ✅ usage by day + destination, balance                         |
| Alchemy  | ⚠️ quota state only — **no billing API exists** (see below)    |
| Others   | implement `SpendProvider` in `src/providers/`                 |

### Alchemy is a special case

Alchemy publishes **no usage or billing API**. Compute-unit consumption is
visible only in the dashboard; probing the plausible endpoints with a valid key
returns 404/429, not data. A usage-polling connector is therefore impossible,
and shipping one would mean detectors that appear to work but can never fire.

What Alchemy does expose for free is the state that matters most: once the
monthly capacity limit is reached, every JSON-RPC call returns a distinctive
429. spend-guard polls one cheap `eth_blockNumber` and alerts **critical** on
that, because it is simultaneously a billing event and an outage — the drain has
already happened, and every app on that key is failing until the cap is raised.

It also distinguishes an exhausted quota from a rejected key, since those need
opposite responses (raise the cap vs. rotate the credential).

Because one Alchemy key is commonly shared across several apps, each entry takes
a `label` so alerts name the right service:

```toml
alchemy_rpc_urls = [
  { label = "trading-base", url = "${BASE_RPC_URL}" },
  { label = "payments-btc", url = "${BITCOIN_RPC_URL}" },
]
```

**Sharing one key across apps defeats attribution.** Alchemy bills and reports
per app, so a shared key makes it impossible to tell which service burned the
quota — or to revoke one without breaking the others. Split the key first; the
labels here are a mitigation, not a substitute.

The interface is two methods — `fetchUsage`, `fetchBalance` — so adding
SendGrid, OpenAI, AWS or Vonage is a small, self-contained contribution.

## Development

```bash
pnpm install
pnpm test      # 42 tests, replays real incidents
pnpm build
```

Detection logic in `src/detectors.ts` is pure and I/O-free, so every rule is
testable against captured provider payloads without network access.

## License

MIT — see [LICENSE](./LICENSE). Contributions welcome, particularly new
provider connectors.
