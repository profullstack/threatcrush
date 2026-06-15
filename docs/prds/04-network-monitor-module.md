# PRD — Network monitor module

- **Status:** Draft · Not started
- **Surface(s):** CLI (`apps/cli/src/modules/network-monitor`, `commands/monitor.ts`)
- **Priority:** P1
- **Owner:** TBD
- **Related:** `docs/PRD.md` §2 · README "Live Attack Detection" · [[01-detection-rule-engine]] · [[02-firewall-auto-remediation]]

## Problem

The README's hero output shows port scans and SYN floods detected across "every
port", and lists `network-monitor` as a bundled core module — but no such module
exists (`apps/cli/src/modules/` has only `log-watcher` and `ssh-guard`).
`commands/monitor.ts` (~237 lines) drives the monitor UX but the connection-level
network detection engine behind the headline is missing.

## Goals

1. Observe TCP/UDP connections across ports (via conntrack / `/proc/net` / netlink — no heavy DPI).
2. Detect port scans and SYN-flood-style patterns.
3. Emit detections through the rule engine ([[01-detection-rule-engine]]); feed remediation ([[02-firewall-auto-remediation]]).
4. Stay lightweight per PRD non-functional perf requirements.

## Non-goals

- Deep packet inspection (requires inline hardware — `docs/FUTURE_PLANS.md`).
- Full IDS/IPS signature matching on payloads.

## Current state

- `commands/monitor.ts` exists; `network-monitor` module does not.
- README claims it as shipping — copy and reality diverge.

## Requirements

1. Connection source adapter (prefer conntrack/`ss`/`/proc/net/*`; document privilege needs).
2. Port-scan heuristic (many ports / short window / single source).
3. SYN-flood heuristic (half-open ratio thresholds).
4. Rule-driven thresholds (no hardcoding) once [[01-detection-rule-engine]] lands.
5. Low idle CPU/memory footprint; graceful `EACCES` degradation.

## Acceptance criteria

- [ ] Simulated nmap scan against the host is detected within the configured window.
- [ ] Detection flows to `detections` and (if enabled) triggers a firewall ban.
- [ ] Idle overhead within PRD perf budget.

## Out of scope / later

- DNS-specific monitoring → [[05-dns-monitor-module]].
- Payload inspection.

## Open questions

- conntrack vs eBPF for connection visibility — eBPF is richer but raises portability/privilege bar. Recommend conntrack for v1.
</content>
