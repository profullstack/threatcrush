# @profullstack/threatcrush-web

The threatcrush.com Next.js app. Hosts the marketing site, auth flow, org dashboards, property manager, and the REST API that CLI / desktop / extension all talk to.

## Dev

```bash
# from repo root
pnpm install
pnpm --filter @profullstack/threatcrush-web dev
# or, as shorthand:
pnpm dev
```

Required env vars (fail-loud if missing):

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`

Optional:

- `COINPAYPORTAL_API_KEY`, `COINPAYPORTAL_BUSINESS_ID`, `COINPAYPORTAL_WEBHOOK_SECRET` — checkout
- `TELNYX_API_KEY`, `TELNYX_PHONE_NUMBER` — SMS OTP
- `NEXT_PUBLIC_SENTRY_DSN` — error reporting (client + server)

`.env` lives at the repo root and is symlinked into this directory so Next.js picks it up automatically.

## Build

```bash
pnpm build                 # next build → .next/standalone/...
```

The production image is built via the repo-root `Dockerfile` and served by Railway.

## API surface

Routes live under `src/app/api/**`. Key ones:

- `POST /api/auth/login` — email + password → session
- `GET /api/auth/me` — profile for a bearer token
- `GET|POST /api/orgs` + `/api/orgs/[id]/...` — orgs / members / servers / properties / runs
- `POST /api/orgs/[id]/runs/pending` — worker claims a queued run (used by threatcrushd)
- `POST /api/orgs/[id]/schedules/tick` — enqueues overdue scheduled runs
- `POST /api/waitlist` + `/api/webhooks/coinpay` — payments

All mutating routes expect a `Bearer` token.

## Pages

- `/` — marketing + install snippet
- `/auth/*` — login, signup, phone verify, forgot-password
- `/org/[slug]` — org dashboard, `/servers`, `/properties` (with detail + run history)
- `/store` + `/store/[slug]` + `/store/publish` — module marketplace (catalog read-only in v0.1.0)
- `/pricing`, `/privacy`, `/terms`, `/usage`

## Testing

```bash
pnpm --filter @profullstack/threatcrush-web test
```

Uses Vitest; config at `vitest.config.ts`.
