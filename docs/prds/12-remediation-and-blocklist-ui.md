# PRD — Remediation & blocklist UI

- **Status:** Draft · Not started
- **Surface(s):** Web/PWA (`apps/web/src/app/org/[slug]`)
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §5 → Remediation history + allowlist/blocklist · [[02-firewall-auto-remediation]] · [[00-detection-data-model]]

## Problem

The PRD dashboard requires remediation history and allowlist/blocklist
management ("what the tool already blocked"), with control actions (unblock,
allowlist). None of this exists in the web app. Operators currently cannot see or
manage what the daemon blocked.

## Goals

1. Remediation history view reading `remediation_actions`.
2. Allowlist/blocklist management UI backed by `allowlists` + remediation actions.
3. Control actions: unblock an IP, add/remove allowlist entry, manually block.
4. Actions propagate to the daemon ([[02-firewall-auto-remediation]]).

## Non-goals

- Bulk import/export of blocklists at launch.
- Policy templates (Phase 2).

## Current state

- No remediation/blocklist UI. Depends on [[00-detection-data-model]] and [[02-firewall-auto-remediation]].

## Requirements

1. **Remediation history**: list of actions (type, target, status, executed_at, expires_at) per server + fleet.
2. **Blocklist view**: currently-active bans with TTL countdown; unblock button.
3. **Allowlist management**: add/remove IP/CIDR/user with note.
4. **Manual block**: form to block an IP with optional TTL.
5. **Propagation**: writes create commands the daemon applies (and confirms back via status).
6. Permission-gated by org role.

## API

- `GET /api/orgs/[id]/remediations`, `POST …/remediations/execute`
- `GET/POST/DELETE /api/orgs/[id]/allowlists`

## Acceptance criteria

- [ ] Remediation history renders with live status.
- [ ] Unblock removes the ban on the host (round-trips to the daemon).
- [ ] Allowlist add prevents future blocks of that target.
- [ ] Manual block reaches the daemon and shows as active.

## Out of scope / later

- Bulk operations, import/export.

## Open questions

- Command propagation channel: does the daemon poll a server queue (like `runs-worker`) for remediation commands? Define the transport.
</content>
