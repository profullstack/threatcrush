# Build the ThreatCrush hardening scanner

> ugig.net gig posting — implements [PRD-03](../03-hardening-scanner.md)

- **Title:** Build the ThreatCrush hardening scanner
- **Skills required:** `typescript`, `nodejs`, `linux`, `ssh-hardening`, `security`, `sysadmin`, `vitest`
- **Budget type:** fixed
- **Budget (USD):** 1,500 – 2,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/hardening-scanner`
- **Spec:** `docs/prds/03-hardening-scanner.md`

## What we need

A key differentiator and an MVP feature that doesn't exist yet: a local hardening
scanner that runs on enrollment and on demand, producing plain-English findings
with recommended fixes and a per-server hardening score.

## Scope

1. The nine initial checks from the PRD: SSH password auth, root SSH login, weak
   SSH config, missing auto security updates, firewall inactive, exposed ports,
   fail2ban present, world-writable sensitive dirs, risky service exposure.
2. Each check returns key, severity, status (pass/warn/fail), explanation, fix.
3. `threatcrush harden` (color report) + `threatcrush harden --json`; auto-run
   after `init`/enrollment; results synced to `hardening_findings` (PRD-00).
4. A hardening score surfaced in `threatcrush status` and the dashboard.

## Acceptance criteria

- All nine checks implemented with fix guidance; runs without root where possible
  and degrades gracefully on `EACCES`.
- Findings persist to `hardening_findings`; score computed and shown in `status`.
- PR with green CI and unit tests covering each check's pass/fail logic.
</content>
