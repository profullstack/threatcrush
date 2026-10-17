---
openprd: "0.2"
id: "0020"
title: "Run our own open IP and domain reputation list"
status: Phases 1-2 shipped, phase 3 in progress
authors:
  - anthony@profullstack.com
created: 2026-10-17
updated: 2026-10-17
repo: profullstack/threatcrush
discussion:
implementation:
  - https://github.com/profullstack/niche-db (reputation-collection, 0.39.0)
  - https://github.com/profullstack/threatcrush (worktree-reputation-pro)
tags: [reputation, blocklist, nichedb, coinpay, api]
supersedes:
superseded-by:
---

## Problem

On 2026-10-17 Spamhaus DBL listed 17 fleet domains and XBL/CSS listed dev2's
IP. The lists that decide whether our mail lands and whether our sites load are
opaque, keyed, and closed to submissions. Anthony: "let's just create our own
public db with paid upgrades and more analysis / threat detection etc. via
nichedb (public) and threatcrush (paid)".

We already hold the raw material: every linked ThreatCrush daemon reports
what it blocks (`/api/ingest`), the fleet's bans feed nichedb's human-reviewed
`/traffic`, and abuse.ch publishes malware infrastructure under free terms.

## Split

| | nichedb.dev (public, free) | threatcrush.com (paid) |
|---|---|---|
| Who | anyone, keyless (metered), more with a free account | any ThreatCrush key; Pro per org |
| IPs | `/traffic` (human-approved fleet bans) + abuse.ch ThreatFox/URLhaus/Feodo | community database (corroboration bar), 7 days free / 90 days Pro |
| Domains | abuse.ch ThreatFox/URLhaus (parents checked), SURBL watch | phase 2 |
| Answer | listed, 0-100 score + reasons, which lists were checked | verdict free; Pro adds history, /24 neighbours, city, score reasons, 10k/day |
| Surfaces | page, API, CLI `nichedb reputation`, MCP `reputation_lookup` / `traffic_list` | API, CLI `threatcrush reputation [subscribe]`, page |

## Phase 1 (this change)

- **nichedb 0.39.0**: `abusech` adapter (threats collection, hourly, CDN /
  resolver / shared-suffix guard), feeds `malware-ips`, `malware-domains`,
  `botnet-c2`; `/reputation`, `/reputation/<q>`, `/api/v1/reputation/<q>`;
  CLI `reputation` and `traffic [<ip>] [--txt]`; MCP `reputation_lookup`,
  `traffic_list`.
- **ThreatCrush**: `GET /api/v1/reputation/<ip>` (key-gated, free vs Pro),
  `GET|POST /api/v1/reputation/subscribe` (CoinPay, crypto only),
  `reputation_subscriptions` table + webhook branch (period stamped once,
  renewals stack), `/reputation` page, CLI `threatcrush reputation <ip>` and
  `reputation subscribe`.
- **Sales are off** until `REPUTATION_PRO_ENABLED=true`. Prices
  ($29/month, $290/year) are placeholders for Anthony to set.

## Phase 2: deeper analysis (Pro) — shipped 2026-10-17

Done: ASN owner + listed-on-same-owner (DB-IP ASN Lite), watch lists + alerts (`reputation_watches`, hourly `/api/v1/reputation/watches/run` from dev2 cron), domains (A/AAAA + nichedb), shared daily allowance (`reputation_take`), bulk (100 free / 1,000 Pro), score v2 (rule class + 30-day decay), ThreatCrush MCP at `/api/mcp`. Human labels: nichedb `/api/v1/traffic/decisions` (TRAFFIC_FEED_TOKEN): a rejection is never published here, an approval lists the source and adds to its score.

1. **ASN and owner**: DB-IP ASN Lite (CC BY 4.0, same monthly loader as
   `geoip.ts`) → AS number, org, prefix; "how much of this ASN is listed"
   as a score input. Show hosting vs residential.
2. **Watch lists + alerts**: `reputation_watches (org_id, indicator, kind)`;
   an hourly job diffs listings and sends through `lib/alerts` (email, push,
   webhooks, SMS via smshub). First use: our own 17 DBL domains and dev2's IP.
3. **Domain reputation on ThreatCrush**: link daemon DNS-monitor lookups and
   web-request Host/Referer to domains; corroborate the same way as IPs.
4. **Persistent allowance**: move `takeLookup` from process memory to a
   `reputation_usage (caller, day, n)` row (or Redis) before selling volume;
   add `x-ratelimit-*` docs and a bulk endpoint (`POST` up to 1,000 IPs).
5. **Score v2**: weight by rule class (exploit > brute force > scanner),
   decay by age, and feed nichedb's human review decisions back as labels.
6. **ThreatCrush MCP**: `reputation_lookup` with the Pro fields for agents
   holding a key.

## Phase 3: distribution and trust

1. **Our own DNSBL zone**: `<rev-ip>.bl.<zone>` answering 127.0.0.x for
   approved /traffic addresses, so mail servers and fail2ban query us like
   Spamhaus. Needs a zone name (Moshpit name per the no-new-ICANN rule) and
   an authoritative server on a box with port 53.
2. **Delisting flow**: a public "this is my address" request on nichedb with
   proof (rDNS, a token at the domain), reviewed in `/traffic/review`.
3. **Feeds out**: RPZ and plain lists per category; push approved addresses to
   AbuseIPDB/StopForumSpam via the abuse-reporter (PRD 0015) once keyed.
4. **Ingest more sensors**: anyone running the daemon contributes by default;
   publish contributor counts on /traffic.

## Open questions for Anthony

- Pro price and whether to sell monthly, yearly or both.
- Whether nichedb should serve full approved IPs keyless (today: newest 100 +
  120 lookups/h keyless, full list with a free account).
- DNSBL zone name (phase 3).
