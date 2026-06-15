# PRD — DNS monitor module

- **Status:** Draft · Not started
- **Surface(s):** CLI (`apps/cli/src/modules/dns-monitor`)
- **Priority:** P1
- **Owner:** TBD
- **Related:** `docs/PRD.md` §2 · README "DNS tunneling, DGA detection" · [[01-detection-rule-engine]]

## Problem

The README hero output shows "DNS tunneling — :53 suspicious TXT queries" and
lists `dns-monitor` as a bundled core module, but it does not exist. DNS-based
exfiltration and DGA beaconing are real threats the product claims to catch.

## Goals

1. Observe DNS query activity on the host (resolver logs / `:53` traffic where available).
2. Detect DNS tunneling indicators (high TXT volume, abnormal query length/entropy).
3. Detect DGA-style domains (entropy / n-gram heuristics).
4. Emit detections via the rule engine.

## Non-goals

- Acting as a DNS resolver / sinkhole (that's the hardware `dns-sinkhole` module).
- Decrypting DoH/DoT.

## Current state

- No module. README copy claims it ships.

## Requirements

1. DNS event source (resolver/query logs, or passive observation of `:53`); document what each environment can provide.
2. Tunneling heuristics: TXT query rate, label length, entropy thresholds (rule-driven).
3. DGA heuristics: domain entropy / dictionary checks.
4. Thresholds via [[01-detection-rule-engine]].

## Acceptance criteria

- [ ] A scripted DNS-tunneling pattern is flagged.
- [ ] A high-entropy DGA-like domain burst is flagged.
- [ ] Low false positives against a normal-traffic fixture corpus.

## Out of scope / later

- Inline DNS blocking / sinkhole (hardware roadmap).

## Open questions

- Which DNS visibility is realistically available on a typical VPS without a local resolver? May need to require systemd-resolved/dnsmasq logging.
</content>
