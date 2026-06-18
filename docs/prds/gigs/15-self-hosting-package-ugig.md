# Build the ThreatCrush self-hosting package

> ugig.net gig posting — implements [PRD-15](../15-self-hosting-package.md)

- **Title:** Build the ThreatCrush self-hosting package
- **Skills required:** `docker`, `docker-compose`, `devops`, `nextjs`, `supabase`, `postgres`, `docs`
- **Budget type:** fixed
- **Budget (USD):** 1,200 – 2,000
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/self-hosting`
- **Spec:** `docs/prds/15-self-hosting-package.md`

## What we need

"Self-hostable" is core to the open-source positioning, but there's no turnkey
self-host package — only a hosted `Dockerfile` + `railway.json`. Deliver a
docker-compose control plane plus the docs to run and enroll against it.

## Scope

1. `docker-compose.yml` bringing up the web/API control plane (BYO Postgres /
   external Supabase recommended to keep the image lean) with healthchecks +
   persistence volumes.
2. A consolidated self-host `.env.example`, clearly marking optional integrations
   (Stripe/CoinPay/AI keys).
3. Documented migration path (`supabase db push` or SQL editor) and a documented
   agent-enrollment flow against `https://my-instance`.
4. Document the local-first / normalized-only ingest privacy posture.

## Acceptance criteria

- `docker compose up` yields a working control plane reachable in a browser.
- A fresh agent enrolls against the self-hosted instance and appears in the
  dashboard; migrations reproducible from a clean DB.
- Self-hosting guide published. PR with green CI.
