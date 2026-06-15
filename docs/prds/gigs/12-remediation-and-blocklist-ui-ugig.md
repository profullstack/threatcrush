# Build the ThreatCrush remediation & blocklist UI

> ugig.net gig posting — implements [PRD-12](../12-remediation-and-blocklist-ui.md)

- **Title:** Build the ThreatCrush remediation & blocklist UI
- **Skills required:** `typescript`, `react`, `nextjs`, `tailwind`, `supabase`, `frontend`
- **Budget type:** fixed
- **Budget (USD):** 1,500 – 2,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/remediation-ui`
- **Spec:** `docs/prds/12-remediation-and-blocklist-ui.md`

## What we need

Operators can't see or manage what the daemon blocked. Build the remediation
history + allowlist/blocklist management UI with control actions that propagate
back to the daemon (PRD-02).

## Scope

1. Remediation history (type, target, status, executed_at, expires_at) per server
   + fleet, reading `remediation_actions`.
2. Blocklist view: active bans with TTL countdown + unblock; allowlist add/remove
   (IP/CIDR/user) with note; a manual-block form with optional TTL.
3. Command propagation to the daemon (define the transport — likely a server
   queue the daemon polls, like `runs-worker`) with status confirmation.
4. `GET/POST …/remediations`, `…/remediations/execute`, `…/allowlists`.
   Role-gated.

## Acceptance criteria

- History renders with live status; unblock round-trips and removes the ban on
  the host; allowlist add prevents future blocks; manual block reaches the daemon.
- PR with green CI.
</content>
