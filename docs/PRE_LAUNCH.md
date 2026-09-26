# ThreatCrush — Launch Checklist

Updated: 2026-09-25 (CLI v0.13.9).

Release pipelines and their evidence live in [`RELEASE_STATUS.md`](RELEASE_STATUS.md);
per-interface and per-channel status in [`SURFACES.md`](SURFACES.md). Environment
variables are listed in [`../.env.example`](../.env.example) and self-hosting in
[`SELF_HOSTING.md`](SELF_HOSTING.md). This file only tracks what still stands
between today and launch.

Production is one self-hosted box behind nginx, deployed by
`.github/workflows/deploy-dev2.yml`, with self-hosted Supabase at
supabase.threatcrush.com.

## Engineering (in flight as PRs)

- [ ] Daemon ↔ cloud pipeline: `threatcrush servers link` / `unlink`, `POST /api/ingest`
      batches (detections, hardening findings, bans, heartbeats), cloud-queued bans
- [ ] Alert delivery from the server: Slack, Discord, webhook, email, PagerDuty and push
- [ ] Extension badge for new org detections
- [ ] Account self-deletion, password reset
- [ ] Module submissions go through admin review
- [ ] Security fixes: client IP from `X-Forwarded-For`, per-phone SMS cap, SSRF-safe alert test-send
- [ ] Installer and Node version requirement
- [ ] `/api/health` checks the database; server-side Sentry for the web app
- [ ] Site copy, `/docs`, privacy policy and terms describe only what exists
- [ ] After merging: smoke-test `curl | sh` → `init` → `install-service` → `servers link`
      on a fresh Ubuntu VM and confirm a detection reaches the dashboard and an alert fires

## Owner-only

Accounts, secrets and decisions nobody else can do.

- [ ] **Desktop signing:** Apple Developer Program + `APPLE_*` secrets; Windows code-signing
      certificate as `WINDOWS_CERTIFICATE` / `WINDOWS_CERTIFICATE_PASSWORD`
      (see [`DESKTOP_RELEASE_TODO.md`](DESKTOP_RELEASE_TODO.md))
- [ ] **GHCR image public:** github.com/orgs/profullstack/packages → `threatcrush` →
      Change visibility → Public
- [ ] **`PKG_SUBMIT_TOKEN`:** a PAT so published releases trigger `submit-packages.yml`
- [ ] **`@threatcrush` npm scope** and token, so the SDK can publish
- [ ] **Extension stores:** Chrome Web Store developer account; Firefox AMO account +
      `WEB_EXT_API_KEY` / `WEB_EXT_API_SECRET`; Safari via the Apple Developer Program
- [ ] **Mobile push:** Firebase project (`google-services.json` as an EAS file variable) for
      Android and APNs credentials in EAS for iOS; Play Console and App Store accounts
      (see [`MOBILE_RELEASE_TODO.md`](MOBILE_RELEASE_TODO.md))
- [ ] **Web push:** generate VAPID keys and set `NEXT_PUBLIC_VAPID_PUBLIC_KEY`,
      `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` in production
- [ ] **Email:** `RESEND_API_KEY` with a verified sending domain (contact form, guide
      downloads, email alerts)
- [ ] **Error reporting:** `SENTRY_DSN` for the web app and the daemon (optional; unset = off)
- [ ] **GitHub:** OAuth provider enabled in Supabase Auth; GitHub App credentials
      (`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_WEBHOOK_SECRET`)
- [ ] **Proxy trust:** set `TRUSTED_PROXY_HOPS` (see `.env.example`) to match the nginx setup
- [ ] **Legal review:** privacy policy (`/privacy`), terms (`/terms`) and the `/investors` wording
- [ ] **Cookie consent:** decide whether the analytics scripts (DataFast, Robauto, Crawlproof)
      need a consent banner for your audience
- [ ] **Pricing:** decide the pricing model; the site says "contact for pricing" until then

## Verify after deploy

- [ ] `curl https://threatcrush.com/api/health` → `200 {"status":"ok","db":"ok"}`
- [ ] Sign up with email + phone (Telnyx SMS arrives), sign in with GitHub, reset a password
- [ ] `threatcrush servers link` on a real server; detections, findings and bans show in the
      dashboard; a test alert reaches each destination type
- [ ] `<link rel="canonical">` on `/`, `/docs`, `/store` and a blog post points at that page
