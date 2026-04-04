# ThreatCrush — Pre-Launch Checklist

Everything you need before going live. Generate these keys, plug them into `.env.local`, and you're ready.

---

## 1. Supabase (Database)

**What:** Hosts all data — users, modules, waitlist, referrals, usage.

**Create project:**
1. Go to https://supabase.com/dashboard → New Project
2. Name: `threatcrush`
3. Region: pick closest to your users
4. Generate a strong DB password (save it)

**Get keys:**
- Project Settings → API → Copy:
  - `Project URL` → `NEXT_PUBLIC_SUPABASE_URL`
  - `anon public` key → `NEXT_PUBLIC_SUPABASE_ANON_KEY`
  - `service_role` key → `SUPABASE_SERVICE_ROLE_KEY`

**Run migrations:**
```bash
# Option 1: Supabase CLI
supabase db push

# Option 2: Management API (if IPv6 issues)
# Copy SQL from supabase/migrations/*.sql and run in SQL Editor
```

**Migrations to run (in order):**
- `20260404140000_modules_marketplace.sql` — modules, versions, installs, reviews
- Plus any waitlist/referral tables from the landing page

```
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_ROLE_KEY=eyJ...
```

---

## 2. CoinPayPortal (Crypto Payments + Usage Billing)

**What:** Handles all crypto payments — one-time purchases, referral payouts, and usage-based AI billing.

**Create business:**
1. Go to https://coinpayportal.com → Sign in
2. Dashboard → Create Business → Name: `ThreatCrush`
3. Add wallet addresses for each crypto you want to accept (BTC, ETH, USDT, SOL, etc.)
4. Business Settings → API Key → Generate

**Get keys:**
- Business ID (from URL or settings page) → `COINPAYPORTAL_BUSINESS_ID`
- API Key → `COINPAYPORTAL_API_KEY`
- Webhook Secret (Settings → Webhooks → Generate) → `COINPAYPORTAL_WEBHOOK_SECRET`

**Set up webhook:**
- URL: `https://threatcrush.com/api/webhooks/coinpay`
- Events: `payment.completed`, `payment.confirmed`

**Set up usage rate table:**
```bash
# Via API or CoinPayPortal dashboard
curl -X POST https://coinpayportal.com/api/businesses/{id}/usage/rates \
  -H "Authorization: Bearer $COINPAYPORTAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action_type": "ai.inference", "cost_usd": 0.003, "unit": "request", "description": "AI model inference"}'

curl -X POST https://coinpayportal.com/api/businesses/{id}/usage/rates \
  -d '{"action_type": "ai.classification", "cost_usd": 0.015, "unit": "request", "description": "Threat classification"}'

curl -X POST https://coinpayportal.com/api/businesses/{id}/usage/rates \
  -d '{"action_type": "ai.summarize", "cost_usd": 0.003, "unit": "request", "description": "Alert summarization"}'

curl -X POST https://coinpayportal.com/api/businesses/{id}/usage/rates \
  -d '{"action_type": "scan.deep", "cost_usd": 0.05, "unit": "scan", "description": "Deep code vulnerability scan"}'
```

```
COINPAYPORTAL_API_KEY=cpk_live_...
COINPAYPORTAL_BUSINESS_ID=uuid-here
COINPAYPORTAL_WEBHOOK_SECRET=whsec_...
COINPAYPORTAL_API_URL=https://coinpayportal.com
```

---

## 3. Stripe (Card Payments)

**What:** Credit/debit card payments for users who prefer fiat.

**Create account:**
1. Go to https://dashboard.stripe.com → Sign up / Sign in
2. Activate your account (requires business verification)

**Get keys:**
- Developers → API Keys → Copy:
  - Publishable key → `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`
  - Secret key → `STRIPE_SECRET_KEY`

**Set up webhook:**
1. Developers → Webhooks → Add Endpoint
2. URL: `https://threatcrush.com/api/webhooks/stripe`
3. Events: `checkout.session.completed`, `payment_intent.succeeded`
4. Copy signing secret → `STRIPE_WEBHOOK_SECRET`

**Create products (optional — can do via API):**
```bash
# Lifetime access product
stripe products create --name="ThreatCrush Lifetime" --metadata[type]=lifetime

# Create price
stripe prices create --product=prod_xxx --unit-amount=49900 --currency=usd
```

```
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_LIFETIME=price_...
STRIPE_PRICE_REFERRAL=price_...
```

---

## 4. OpenAI (AI-Enhanced Modules) — Optional

**What:** Powers AI-enhanced modules (threat classification, smart alerting, module metadata generation).

**Get key:**
1. Go to https://platform.openai.com/api-keys
2. Create new secret key → `OPENAI_API_KEY`

**Models used:**
- `gpt-4o-mini` — Module metadata generation, tag extraction
- `gpt-4o` — Threat classification, deep analysis (usage-billed to user)

```
OPENAI_API_KEY=sk-...
```

---

## 5. Anthropic (AI-Enhanced Modules) — Optional

**What:** Alternative/additional AI provider for security analysis.

**Get key:**
1. Go to https://console.anthropic.com/settings/keys
2. Create key → `ANTHROPIC_API_KEY`

```
ANTHROPIC_API_KEY=sk-ant-...
```

---

## 6. Railway (Deployment)

**What:** Hosts the ThreatCrush web app + API.

**Already configured** — deploys on push to `master`.

**Verify:**
```bash
cd ~/src/threatcrush
railway status
# Should show: Service: threatcrush.com, Environment: production
```

**Custom domain:**
1. Railway dashboard → Settings → Domains
2. Add `threatcrush.com`
3. Point DNS: CNAME to the Railway domain

**Environment variables:**
Add all the keys above to Railway:
```bash
railway variables set NEXT_PUBLIC_SUPABASE_URL=...
railway variables set NEXT_PUBLIC_SUPABASE_ANON_KEY=...
railway variables set SUPABASE_SERVICE_ROLE_KEY=...
railway variables set COINPAYPORTAL_API_KEY=...
railway variables set COINPAYPORTAL_BUSINESS_ID=...
railway variables set COINPAYPORTAL_WEBHOOK_SECRET=...
railway variables set STRIPE_SECRET_KEY=...
railway variables set STRIPE_WEBHOOK_SECRET=...
railway variables set NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=...
railway variables set OPENAI_API_KEY=...
```

---

## 7. GitHub (CI/CD Secrets)

**What:** Powers automated releases, npm publishing, and package submission.

**Required secrets** (Settings → Secrets → Actions):

| Secret | Where to get it | Used by |
|--------|----------------|---------|
| `NPM_TOKEN` | npmjs.com → Access Tokens → Generate (Automation) | npm-publish.yml |
| `PKG_SUBMIT_TOKEN` | GitHub → Settings → Developer Settings → PAT (repo, workflow scope) | desktop-release.yml, submit-packages.yml |

**Optional secrets** (for desktop code signing + package managers):

| Secret | Where to get it | Used by |
|--------|----------------|---------|
| `APPLE_CERTIFICATE` | Apple Developer → Certificates (base64 encoded .p12) | desktop-release.yml |
| `APPLE_CERTIFICATE_PASSWORD` | Password for the .p12 | desktop-release.yml |
| `APPLE_ID` | Your Apple ID email | desktop-release.yml (notarization) |
| `APPLE_APP_SPECIFIC_PASSWORD` | appleid.apple.com → App-Specific Passwords | desktop-release.yml |
| `APPLE_TEAM_ID` | Apple Developer → Membership → Team ID | desktop-release.yml |
| `KEYCHAIN_PASSWORD` | Any strong password (used in CI only) | desktop-release.yml |
| `WINDOWS_CERTIFICATE` | Code signing cert (base64 encoded .pfx) | desktop-release.yml |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password for the .pfx | desktop-release.yml |
| `AUR_SSH_KEY` | ssh-keygen → upload pubkey to aur.archlinux.org (base64) | submit-packages.yml |
| `GPG_PRIVATE_KEY` | gpg --export-secret-keys (base64) | submit-packages.yml (APT/RPM) |
| `GPG_PASSPHRASE` | Your GPG passphrase | submit-packages.yml |
| `CHOCOLATEY_API_KEY` | chocolatey.org → Account → API Key | submit-packages.yml |

---

## 8. npm (CLI Publishing)

**What:** Publishes `@profullstack/threatcrush` to npm.

**Already configured** — logged in as `chovy`.

**For CI publishing:**
1. Go to https://www.npmjs.com → Access Tokens
2. Generate → Automation token
3. Add as `NPM_TOKEN` in GitHub secrets

---

## 9. Chrome Web Store + Firefox AMO (Extension Publishing)

**Chrome Web Store:**
1. Go to https://chrome.google.com/webstore/devconsole
2. Pay $5 one-time developer fee
3. Upload built zip from `extension/dist/chrome-vX.X.X.zip`
4. Fill in store listing (screenshots, description)

**Firefox AMO:**
1. Go to https://addons.mozilla.org/developers/
2. Create account (free)
3. Upload built zip from `extension/dist/firefox-vX.X.X.zip`

**Build extension:**
```bash
cd extension && pnpm install && node scripts/build.js all
# Outputs: dist/chrome-v0.1.10.zip, dist/firefox-v0.1.10.zip
```

---

## 10. Domain & DNS

**threatcrush.com:**
- Point to Railway: CNAME → `threatcrush-production.up.railway.app`
- Or A record if Railway provides IP

**Verify:**
```bash
dig threatcrush.com CNAME
curl -I https://threatcrush.com
```

---

## Full .env.local Template

```bash
# Supabase
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_ROLE_KEY=eyJ...

# CoinPayPortal
COINPAYPORTAL_API_KEY=cpk_live_...
COINPAYPORTAL_BUSINESS_ID=
COINPAYPORTAL_WEBHOOK_SECRET=whsec_...
COINPAYPORTAL_API_URL=https://coinpayportal.com

# Stripe
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_LIFETIME=price_...
STRIPE_PRICE_REFERRAL=price_...

# AI (optional — for AI-enhanced modules)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# App
NEXT_PUBLIC_APP_URL=https://threatcrush.com
```

---

## Launch Order

1. ✅ Create Supabase project → run migrations
2. ✅ Create CoinPayPortal business → set up wallets + webhook + rate table
3. ✅ Set up Stripe → products + webhook
4. ✅ Add all env vars to Railway
5. ✅ Add GitHub secrets (at minimum: NPM_TOKEN)
6. ✅ Point domain DNS
7. ✅ Test: waitlist signup, payment flow, referral link, module store
8. 🚀 Launch — announce on social, push CLI to npm, start referral program
