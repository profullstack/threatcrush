---
openprd: "0.2"
id: "0019"
title: "Cover the server half of a unified security platform"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-10-17
updated: 2026-10-17
repo: profullstack/threatcrush
discussion: https://github.com/profullstack/threatcrush/issues/312
implementation:
tags: [roadmap, competitive, heimdal, patching, dns-blocking, privileged-access, fim, edr, compliance, msp]
supersedes:
superseded-by:
---

## Problem

Unified security platforms such as [Heimdal](https://heimdalsecurity.com/) sell
"one platform, total security" to enterprises, MSPs and MSSPs: DNS security,
patch and asset management, privileged access, ransomware protection, EDR/XDR,
a managed SOC, compliance mapping and PSA/RMM integrations, all behind one
console. That suite is built around the **Windows endpoint**: antivirus,
BitLocker, USB control, application control, remote desktop and email
security make up most of the module list.

**Linux servers are where these suites are thinnest, and that is where
ThreatCrush already lives.** The daemon reads logs, watches connections, bans
attackers, runs hardening checks and reports to a fleet dashboard. Most of
Heimdal's categories have a server-side equivalent ThreatCrush could offer by
extending code it already has, rather than by entering a new market.

This PRD is a comparison against Heimdal's module list (2026-10-17). It keeps
the modules that make sense on a server, drops the rest, and points each
requirement at the PRD that already covers part of it so nothing is specified
twice.

## Goals

- A buyer comparing ThreatCrush to a unified platform finds a server-side
  answer for patching, DNS protection, privileged access, ransomware, EDR,
  compliance, triage and MSP integration.
- Each capability builds on an existing module or command (`scan --deps`, `harden`,
  `dns-monitor`, `feodo-tracker`, `ssh-guard`, watchdog, attack map, teams and
  fleets, webhooks) before anything new is written.
- MSPs can run ThreatCrush for many customers from one install.

## Non-Goals

- Windows/macOS endpoint protection: antivirus, firewall, BitLocker, USB
  control, application control.
- Email security and email fraud prevention.
- Remote desktop (that is PairUX).
- Home-user products.
- A staffed 24/7 SOC. Triage is automated (R8).
- Any hack-back or countermeasure beyond defending the host.

## Users

- Small teams running their own Linux servers who want one agent instead of
  five tools.
- MSPs and MSSPs who already sell a Windows endpoint suite and have no good
  answer for their customers' servers.

## Requirements

Ordered by value for effort. Each maps to one issue.

- R1 [P0] **Patch status** ([#312](https://github.com/profullstack/threatcrush/issues/312)).
  Inventory OS packages (dpkg/rpm/apk), match them against OSV and the
  Ubuntu/Debian security trackers, and report which hosts and CVEs have a fix
  available, both per host and per fleet. Phase 2: queue "apply security
  updates" from the dashboard (opt-in, dry-run first). App lockfiles stay in
  [0002](./0002-detect-vulnerable-and-malicious-dependencies-on-running-servers.md).
- R2 [P0] **Block known-bad domains and C2 IPs** ([#304](https://github.com/profullstack/threatcrush/issues/304)).
  Blocklists from URLhaus, ThreatFox and Feodo, enforced at the local resolver
  and as nft egress drops, with an allowlist and a dry-run mode. Extends
  [0011](./0011-catch-the-exfiltration-channel-that-survives-egress-filtering.md)
  from detecting to blocking.
- R3 [P0] **Privileged access and identity** ([#305](https://github.com/profullstack/threatcrush/issues/305)).
  A log of every sudo, su and root login; alerts on sudoers, uid-0 and sudo-group
  changes; a successful login from a country or ASN not seen before for that user;
  optional tlog session recording. Builds on
  [0007](./0007-tell-ssh-compromise-apart-from-ssh-background-noise.md), which
  already covers `authorized_keys` and a success that follows failures.
- R4 [P1] **Action Center** ([#306](https://github.com/profullstack/threatcrush/issues/306)).
  One web + TUI view combining watchdog events, the attack map, host status
  and queued actions.
- R5 [P1] **Compliance report** ([#307](https://github.com/profullstack/threatcrush/issues/307)).
  Tag `harden` and [0005](./0005-catch-the-misconfigurations-that-actually-get-servers-breached.md)
  checks with CIS Benchmark ids; export per host and per fleet. Evidence for an
  auditor, not a certification claim.
- R6 [P1] **File integrity + ransomware canaries** ([#308](https://github.com/profullstack/threatcrush/issues/308)).
  Baseline hashes for /etc, web roots and PATH binaries; canary files; a
  mass-rewrite/entropy heuristic with an opt-in process kill.
- R7 [P2] **EDR** ([#309](https://github.com/profullstack/threatcrush/issues/309)).
  Process-level detection via auditd first, then eBPF: reverse shells, a web-server
  user spawning shells, crypto-miners, execution from world-writable
  directories. Events go into the existing rule engine, auto-ban and watchdog.
- R8 [P2] **AI triage** ([#310](https://github.com/profullstack/threatcrush/issues/310)).
  An LLM summary and a recommended action for each high or critical event,
  applied with one click and never automatically beyond what the existing
  auto-ban rules already do; exposed over MCP.
- R9 [P2] **PSA/RMM tickets** ([#311](https://github.com/profullstack/threatcrush/issues/311)).
  HaloPSA and ConnectWise Manage first, with dedupe and auto-close, and a team/fleet →
  PSA client mapping. Builds on
  [0006](./0006-route-alerts-so-they-keep-being-read.md).

## UX Notes

- Every new blocking or killing action ships with dry-run first and an event
  per action, so a false positive can be undone in one click. The
  2026-09-25 port-scan self-ban is the reason.
- New checks get the usual surfaces: CLI subcommand, TUI panel, dashboard
  view, MCP tool.

## Success Metrics

- Fleet dashboard shows a CVE-with-fix count for every linked host (R1).
- At least one C2/blocklist hit blocked on the fleet with zero allowlist
  complaints over 30 days (R2).
- One MSP running more than one customer fleet with tickets flowing into their PSA (R9).

## Risks & Open Questions

- R1 phase 2 (remote patching) runs package upgrades as root from a dashboard
  click. It needs a separate opt-in and an audit log before anyone enables it.
- R2 resolver integration differs per distro (systemd-resolved, dnsmasq,
  unbound). Start with whichever the dev2 fleet uses.
- R7 eBPF needs a recent kernel and CAP_BPF. auditd is the baseline.
- R8 sends event context to an LLM provider. It must be opt-in per fleet, with
  IPs and hostnames only, never log bodies with credentials.
- Pricing: whether these are core, paid modules, or an MSP tier is open.
