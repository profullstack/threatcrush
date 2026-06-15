# PRD — Hardening scanner

- **Status:** Draft · Not started
- **Surface(s):** CLI (`apps/cli/src/commands`, new module)
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §4 "Hardening checks" · [[00-detection-data-model]] · [[11-dashboard-hardening-findings]]

## Problem

Hardening checks are an MVP feature in the master PRD and a key differentiator
("how to harden the box further"), but there is **no hardening scanner** — no
`harden` command and no checks engine (`grep -ri harden apps/cli/src` only hits
the systemd unit file). The first-run UX in the PRD ("Initial hardening scan
runs → user sees findings") cannot happen today.

## Goals

1. A local hardening scanner that runs on enrollment and on demand.
2. Plain-English findings with pass/warning/fail + recommended fix.
3. Persist findings to `hardening_findings` and compute a per-server hardening score.
4. Optional safe autofix for low-risk items (later).

## Non-goals

- Full CIS / STIG benchmark coverage at launch.
- Compliance reporting (SOC2/HIPAA/PCI — community module).
- Autofix of risky items.

## Current state

- No scanner. `threatcrush init` auto-detects services but does not assess posture.

## Requirements (initial checks, per PRD §4)

1. SSH password auth enabled.
2. Root SSH login enabled.
3. Weak SSH config patterns.
4. Missing automatic security updates.
5. Firewall inactive.
6. Common exposed ports.
7. fail2ban present.
8. World-writable dirs in sensitive locations.
9. Risky service exposure.

Each check: key, severity, status (pass/warn/fail), explanation, recommended fix.

## UX / surface

- `threatcrush harden` — run scan, print report (color-coded), exit non-zero on fails optionally.
- `threatcrush harden --json` — machine output.
- Auto-run after `init`/enrollment; results synced to `hardening_findings`.
- Score surfaced in `threatcrush status` and the dashboard ([[11-dashboard-hardening-findings]]).

## Acceptance criteria

- [ ] All 9 checks implemented with fix guidance.
- [ ] Findings persist to `hardening_findings` and render in the dashboard.
- [ ] Hardening score computed and shown in `status` + dashboard.
- [ ] Runs without root where possible; degrades gracefully on `EACCES`.

## Out of scope / later

- Autofix (`--fix`) for safe items — separate fast-follow.
- Posture diffing over time (Phase 3).

## Open questions

- Scoring formula (weighted by severity?) — define before dashboard work.
</content>
