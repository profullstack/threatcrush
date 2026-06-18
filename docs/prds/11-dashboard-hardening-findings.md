# PRD — Dashboard hardening findings

- **Status:** Draft · Not started
- **Surface(s):** Web/PWA (`apps/web/src/app/org/[slug]`)
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §5 → Findings view · [[03-hardening-scanner]] · [[00-detection-data-model]]

## Problem

The PRD's first-run flow ends with "user sees findings and recommended actions",
and the Findings view is a core dashboard surface. Neither the
`hardening_findings` data nor the UI exists today. Without it, the hardening
scanner ([[03-hardening-scanner]]) has nowhere to surface its results in the web app.

## Goals

1. A findings view per server (and a fleet roll-up) reading `hardening_findings`.
2. Pass/warning/fail states with plain-English explanation + recommended fix.
3. Per-server hardening score + fleet posture summary.
4. Resolve/acknowledge a finding; re-scan reflects updated state.

## Non-goals

- One-click autofix from the web (CLI-side, later).
- Posture diffing over time (Phase 3).

## Current state

- No findings UI; `org/[slug]/servers/[id]` shows server detail without hardening.
- Depends on [[00-detection-data-model]] (`hardening_findings`) and [[03-hardening-scanner]].

## Requirements

1. **Server findings tab** on `servers/[id]`: list grouped by status/severity, each with fix guidance.
2. **Hardening score** badge on server detail + overview.
3. **Fleet view**: servers ranked by posture / number of fails.
4. **Actions**: acknowledge / mark resolved (writes `hardening_findings.status`).
5. PWA-friendly responsive layout.

## API

- `GET /api/orgs/[id]/servers/[server_id]/findings`
- `PATCH …/findings/[id]` (status)

## Acceptance criteria

- [ ] Findings render with severity, explanation, fix.
- [ ] Hardening score shown on server + overview.
- [ ] Acknowledge/resolve persists and survives re-scan correctly.

## Out of scope / later

- Web-initiated autofix.

## Open questions

- Should resolving in the UI suppress until next scan, or require the scanner to confirm? (Recommend scanner confirms.)
