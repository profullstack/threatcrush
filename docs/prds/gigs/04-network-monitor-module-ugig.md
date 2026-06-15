# Build the ThreatCrush network monitor module

> ugig.net gig posting — implements [PRD-04](../04-network-monitor-module.md)

- **Title:** Build the ThreatCrush network monitor module
- **Skills required:** `typescript`, `nodejs`, `linux`, `networking`, `conntrack`, `security`, `performance`
- **Budget type:** fixed
- **Budget (USD):** 2,000 – 3,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/network-monitor`
- **Spec:** `docs/prds/04-network-monitor-module.md`

## What we need

The README's hero output shows port scans and SYN floods detected across "every
port" and lists `network-monitor` as a bundled module — but it doesn't exist.
Build a lightweight connection-level monitor (no heavy DPI) that powers the
headline detections.

## Scope

1. A connection source adapter (prefer conntrack / `ss` / `/proc/net/*`;
   document privilege needs) — low idle CPU/memory.
2. Port-scan heuristic (many ports / short window / single source) and SYN-flood
   heuristic (half-open ratio).
3. Thresholds driven by the rule engine (PRD-01), not hardcoded; detections flow
   to `detections` (PRD-00) and can trigger firewall bans (PRD-02).
4. Graceful `EACCES` degradation.

## Acceptance criteria

- A simulated `nmap` scan against the host is detected within the configured
  window and (if enabled) triggers a ban.
- Idle overhead stays within the PRD perf budget.
- PR with green CI and a fixture-based test for the scan/flood heuristics.
</content>
