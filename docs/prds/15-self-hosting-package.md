# PRD — Self-hosting package

- **Status:** Draft · Not started
- **Surface(s):** Web/Ops (`Dockerfile`, new `docker-compose.yml`, docs)
- **Priority:** P1
- **Owner:** TBD
- **Related:** `docs/PRD.md` §8 "Self-hosting", §10 "Privacy" · `docs/PRE_LAUNCH.md`

## Problem

"Self-hostable" and "keep all data in user control" are core to the open-source
positioning, and the PRD requires a docker-compose setup, env-based config,
documented migration, and a documented agent enrollment flow. Today there is a
`Dockerfile` + `railway.json` (hosted deploy), but no turnkey self-host package
or docs. OSS users cannot stand up their own control plane.

## Goals

1. A `docker-compose.yml` that brings up the web/API control plane (+ documented Supabase/Postgres choice).
2. Env-var-driven config with a documented `.env` template.
3. Documented migration process for self-hosters.
4. Documented agent enrollment against a self-hosted instance.

## Non-goals

- Bundling a full Supabase stack if too heavy — may document "bring your own Postgres + Supabase" instead.
- Multi-tenant MSP self-host (cloud edition concern).

## Current state

- `Dockerfile` (web, `output: standalone`), `railway.json` for hosted.
- `docs/PRE_LAUNCH.md` documents hosted setup (Supabase/CoinPay/Stripe/Railway), not self-host.
- No compose file; migrations exist under `supabase/migrations/`.

## Requirements

1. **Compose**: web/API service + DB option; healthchecks; volumes for persistence.
2. **Config**: consolidated `.env.example` for self-host; clearly mark which integrations are optional (Stripe/CoinPay/AI keys).
3. **Migrations**: documented `supabase db push` (or SQL-editor) path for self-hosters.
4. **Enrollment**: doc + command for pointing a CLI/agent at `https://my-instance` and enrolling a server.
5. **Privacy posture**: document local-first / normalized-only ingest in self-host mode.

## Acceptance criteria

- [ ] `docker compose up` yields a working control plane reachable in a browser.
- [ ] A fresh agent enrolls against the self-hosted instance and appears in the dashboard.
- [ ] Migration steps reproducible from clean DB.
- [ ] Docs published (self-hosting guide).

## Out of scope / later

- One-click cloud-marketplace images (DO/Linode).

## Open questions

- Bundle Supabase (heavy) vs document external Supabase/Postgres? (Recommend external/BYO Postgres for v1 to keep the image lean.)
</content>
