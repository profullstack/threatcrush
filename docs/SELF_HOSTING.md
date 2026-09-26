# Self-Hosting ThreatCrush

This guide covers deploying the ThreatCrush web control plane on your own infrastructure.

## Prerequisites

- Docker and Docker Compose
- A Supabase project (free tier works) or external PostgreSQL
- Node.js 22+ (for running the CLI/agent)

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/profullstack/threatcrush.git
cd threatcrush

# 2. Configure environment
cp .env.example .env
# Edit .env with your Supabase credentials (required)

# 3. Apply database migrations
# In Supabase Dashboard: SQL Editor → paste each file from supabase/migrations/ in order
# Or use the Supabase CLI:
# supabase db push

# 4. Start the control plane
docker compose up -d

# 5. Verify: 200 {"status":"ok","db":"ok",...}; 503 if the database is unreachable
curl http://localhost:3000/api/health
```

The image's `HEALTHCHECK` polls the same endpoint, so `docker compose ps` shows
the container as unhealthy while the database is down.

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_SUPABASE_URL` | Your Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase anon/public key |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key |
| `SETTINGS_ENCRYPTION_KEY` | 32-byte base64 key for encrypting secrets |

### Optional

`.env.example` lists every variable the web app reads, with a one-line note
each. The ones a self-hoster most often sets:

| Variable | Description |
|----------|-------------|
| `RESEND_API_KEY` | Outgoing email (contact form, whitepaper, email alerts) |
| `COINPAYPORTAL_*`, `COINPAY_WEBHOOK_SECRET` | CoinPayPortal crypto payments |
| `NEXT_PUBLIC_VAPID_PUBLIC_KEY` | Web Push VAPID public key |
| `VAPID_PRIVATE_KEY` | Web Push VAPID private key |
| `NEXT_PUBLIC_GITHUB_OAUTH_ENABLED` | `true` shows "Continue with GitHub" on login/signup. Enable the GitHub provider in Supabase Auth first; read at build time |
| `SENTRY_DSN` | Report server-side route errors to Sentry. Unset = off, no network |
| `TRUSTED_PROXY_HOPS` | Reverse proxies in front of the app (default 1), for rate limiting by client IP |

Generate VAPID keys: `npx web-push generate-vapid-keys`

## Database Migrations

Apply migrations in order from `supabase/migrations/`:

```bash
# Using Supabase CLI
supabase db push

# Or manually in SQL Editor, apply each file chronologically:
# 20260404120000_waitlist.sql
# 20260404120100_referrals.sql
# ... (all files in order)
# 20260601000000_detection_core.sql  (detection/remediation/alerting tables)
```

## Agent Enrollment

Once the control plane is running, enroll agents on your servers:

```bash
# 1. Install the CLI on the target server
npm i -g @profullstack/threatcrush

# 2. Point to your self-hosted instance
export THREATCRUSH_API_URL=https://your-instance.example.com

# 3. Login
threatcrush login

# 4. Initialize and start
threatcrush init
threatcrush start

# 5. Install as systemd service (optional)
sudo threatcrush install-service
```

## Privacy

- **Normalized detections only** by default -- no raw logs are stored
- All data stays in your Supabase/Postgres instance
- The agent sends only structured detection events (severity, title, source IP)
- No telemetry phones home unless you opt in

## Updating

```bash
git pull
docker compose build
docker compose up -d
```

## Architecture

```
[Server 1]                    [Your Control Plane]
  threatcrushd ──POST /api/ingest──→ Next.js API
                                        ↓
[Server 2]                        Supabase/Postgres
  threatcrushd ──POST /api/ingest──→    ↓
                                    Dashboard (PWA)
                                        ↓
                                    Alerts (Slack/Discord/etc)
```
