# PRD — Firewall auto-remediation

- **Status:** Draft · Not started
- **Surface(s):** CLI (`apps/cli/src/daemon`, new module `firewall-rules`)
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §3 "Auto-remediation", §"Firewall abstraction" · [[00-detection-data-model]] · [[12-remediation-and-blocklist-ui]]

## Problem

The README advertises `firewall-rules` as a core module that "auto-blocks via
iptables/nftables", and auto-remediation is a top-line MVP feature. In reality
there is **zero firewall code** — the only `iptables/nftables/firewall` reference
in `apps/cli/src` is a string in `index.ts`. The product's central promise
("what the tool already blocked") is currently vapor.

## Goals

1. Block offending IPs via a firewall backend in response to detections.
2. Abstract the backend so nftables and iptables are interchangeable (PRD §"Firewall abstraction").
3. Safe-by-default: dry-run mode, allowlist, ban expiry, full audit trail, easy unblock.
4. Persist actions to `remediation_actions` ([[00-detection-data-model]]).

## Non-goals

- Inline packet blocking / IPS (hardware roadmap, `docs/FUTURE_PLANS.md`).
- Cross-host coordinated blocking (later).

## Current state

- No firewall adapter exists.
- Detections (once [[01-detection-rule-engine]] lands) carry remediation suggestions but nothing acts on them.

## Requirements

1. **Adapters**: `nftables` first, `iptables` fallback; auto-detect available backend; generic interface so others can be added.
2. **Actions**: temporary ban (with expiry), permanent blocklist, unblock.
3. **Dry-run mode**: log intended action without executing (default until operator opts in).
4. **Allowlist**: never block allowlisted IPs/CIDRs (reads from `allowlists`).
5. **Audit trail**: every action recorded locally and synced to `remediation_actions`.
6. **Expiry worker**: daemon worker unblocks expired bans (mirror `runs-worker` pattern).
7. **Privilege**: handle `EACCES` gracefully when daemon lacks CAP_NET_ADMIN; surface a clear hardening recommendation instead of crashing (consistent with how built-in modules handle `EACCES`).

## UX / surface

- `threatcrush block <ip> [--ttl 1h]` / `unblock <ip>` / `blocklist` / `allowlist add|remove <ip>`.
- `[remediation]` config block in `threatcrushd.conf` (backend, default ttl, dry_run, allowlist).
- Auto-trigger from detections at/above a configurable severity.

## Acceptance criteria

- [ ] nftables + iptables adapters pass integration tests in a container.
- [ ] Dry-run produces an audit entry but no firewall change.
- [ ] Allowlisted IP is never blocked even on a matching detection.
- [ ] Expired bans are removed automatically; manual unblock works.
- [ ] Actions appear in the dashboard via `remediation_actions`.

## Out of scope / later

- Geo/ASN blocking (community `geo-blocker` module).
- Rollback of large blocklists / import-export.

## Open questions

- Default to dry-run at install, or auto-enable blocking after first scan? (Recommend dry-run default + prompt.)
</content>
