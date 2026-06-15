# Build the ThreatCrush dashboard hardening findings view

> ugig.net gig posting — implements [PRD-11](../11-dashboard-hardening-findings.md)

- **Title:** Build the ThreatCrush dashboard hardening findings view
- **Skills required:** `typescript`, `react`, `nextjs`, `tailwind`, `supabase`, `frontend`
- **Budget type:** fixed
- **Budget (USD):** 1,200 – 2,000
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/dashboard-findings`
- **Spec:** `docs/prds/11-dashboard-hardening-findings.md`

## What we need

The first-run flow ends with "user sees findings and recommended actions," but
neither the data nor the UI exists. Build the findings view that surfaces the
hardening scanner's results (PRD-03) from `hardening_findings` (PRD-00).

## Scope

1. A server findings tab on `servers/[id]`: grouped by status/severity, each with
   plain-English explanation + recommended fix.
2. Per-server hardening score badge on server detail + overview; a fleet view
   ranking servers by posture.
3. Acknowledge / mark resolved actions (`PATCH …/findings/[id]`).
4. `GET /api/orgs/[id]/servers/[server_id]/findings`. Responsive / PWA-friendly.

## Acceptance criteria

- Findings render with severity, explanation, fix; score shown on server +
  overview.
- Acknowledge/resolve persists and survives a re-scan correctly.
- PR with green CI.
</content>
