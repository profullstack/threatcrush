# Auto-defence

ThreatCrush bans attacking addresses by itself, and the dashboard lets you add
and remove bans by hand. This is on by default.

## The ladder

A ban's length comes from where the address sits on the Fibonacci ladder, in
minutes:

| Offence | 1  | 2  | 3  | 4  | 5  | 6   | 7   | 8   |
|---------|----|----|----|----|----|-----|-----|-----|
| Ban     | 1m | 2m | 3m | 5m | 8m | 13m | 21m | 34m |

It keeps climbing, clamped at `max_ban` (24h by default). A first offence costs
an address a minute — cheap enough that a false positive is barely an incident —
while a host that keeps coming back is at hours by its tenth visit without
anyone writing a permanent rule.

An offence counts towards the next ban for `strike_memory` (24h by default).
After that the address is forgiven and starts again at one minute, so a recycled
address is not punished for its predecessor's behaviour.

Nothing is ever permanent. Every ban expires, which is what keeps a blocklist
from turning into an unreviewable accretion that eventually blocks something
important for a reason nobody remembers.

## What gets banned

Detections of severity `high` and above — SSH brute force, invalid users, and
web attacks from the access log. Routine 4xx noise is `low` and never triggers a
ban; a paywall returning 402 to thousands of crawlers is traffic, not an attack.

### Web attacks

Every nginx request — its request line, User-Agent and Referer — is scored
against the OWASP Core Rule Set (v4.29.0, paranoia level 1): the rules whose
targets an access log records, ported by `scripts/build-crs-rules.mjs`. CRS
anomaly scoring applies: each matching rule adds its severity's points (CRITICAL
5, ERROR 4, WARNING 3, NOTICE 2), and a request is an attack when the total
reaches the threshold, 5 by default — one CRITICAL rule.

| Score                 | Event severity | Banned at the default `min_severity`? |
|-----------------------|----------------|---------------------------------------|
| below the threshold   | `low`          | no                                    |
| at the threshold      | `high`         | yes                                   |
| twice the threshold   | `critical`     | yes                                   |

Set `min_severity = "critical"` to ban only on two or more matching rules. Each
event carries `crs_score`, `crs_threshold`, `crs_rule_ids` and `attack_type`.

What an access log cannot show, these rules cannot see: request bodies,
cookies and other headers. The two libinjection rules (942100 SQLi, 941100
XSS) are not ported, so a bare `1' OR 1=1` scores nothing; `UNION SELECT`,
`SLEEP(`, script tags, traversal and the rest do.

One ported rule is off by default, because with bans automatic it would ban
ordinary visitors:

| Rule   | Why it is off                                                                                                  |
|--------|----------------------------------------------------------------------------------------------------------------|
| 941130 | Matches `xhtml` in the request path, so every request for a `*.xhtml` page — JSF and other Java sites — scores as XSS. |

`exclude_rules` adds to that list; it does not replace it, so switching off a
rule of your own never switches 941130 back on. `include_rules` is the only way
to re-enable a default-off rule. A rule in both lists stays off.

```toml
[detection]
anomaly_threshold = 5         # CRS inbound threshold
exclude_rules = [942550]      # CRS rule ids to switch off, like SecRuleRemoveById
include_rules = [941130]      # default-off rules to switch back on
```

## What can never be banned

Enforced when the rule is written, not when the decision is made, so no detector
however wrong can cause a lockout:

- loopback, `127.0.0.0/8` and `::1`
- private ranges: `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `fc00::/7`, `fe80::/10`
- the default gateway
- the SSH client that started the daemon
- anything in `[remediation] protected`

`threatcrush allowlist` prints the resolved list.

## The dashboard

`threatcrush monitor --tui`

- `tab` cycles focus: feed → top threats → banned
- `↑ ↓` scroll the feed, or move the selection in the two lists
- `b` bans the selected address, `u` unbans it
- a click selects a row and focuses its panel in one go

A banned source is marked `✖` in TOP THREATS, a protected one `⛊`. The BANNED
panel shows each ban's offence number and the time it has left.

Unbanning by hand also clears the address's strike history: you are overruling
the detection, so the next offence starts again at one minute rather than
resuming the ladder.

## Backends

Detected at startup, in order: **fail2ban** (if the server is running),
**nftables**, **iptables**. With none of them, bans are simulated and the
dashboard says so rather than implying the host is defended.

With fail2ban, ThreatCrush installs a `threatcrush` jail that deliberately
matches nothing — detection already happened here — and bans through
`fail2ban-client set threatcrush banip`. Expiry stays ours, because a jail has
one bantime and the ladder needs a different one per offender; the jail's own
bantime is only a backstop for a daemon that dies holding bans.

## Configuration

```toml
[remediation]
enabled = true
mode = "enforce"              # or "dry_run" to log without blocking
backend = "auto"              # auto | fail2ban | nftables | iptables
min_severity = "high"
max_ban = "24h"
strike_memory = "24h"
protected = ["203.0.113.7/32"]
protect_current_ssh_client = true
```

## From the CLI

```sh
threatcrush blocklist            # what is banned, why, and for how long
threatcrush block 45.33.22.11    # ban by hand (climbs the ladder too)
threatcrush block 45.33.22.11 --ttl 2h
threatcrush unblock 45.33.22.11
threatcrush allowlist            # what can never be banned
```

Banning needs the daemon control token, which is readable by root (system mode)
or by the user running the daemon (user mode). Reading the blocklist does not:
anyone who can already query the daemon can see what it blocked.
