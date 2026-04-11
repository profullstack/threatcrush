# ThreatCrush TODO

Generated: 2026-04-11

---

## 🔴 Blockers (Must fix before production launch)

### 1. Phone / SMS Verification ✅ FIXED
- [x] **Replaced stub phone verification** — `src/app/api/auth/verify-phone/route.ts` now calls `supabase.auth.verifyOtp()` to validate the OTP against Supabase's stored code.
- [x] **Created `send-phone-code` endpoint** — `src/app/api/auth/send-phone-code/route.ts` triggers Supabase OTP generation, which fires the Telnyx webhook.
- [x] **Updated frontend** — `src/app/auth/verify/page.tsx` now has a "Send verification code" button and proper OTP input flow. Removed "Beta: Any 6-digit code" warning.
- [x] **Tests updated** — Added tests for invalid OTP, wrong user OTP, and new `send-phone-code` endpoint tests.
- [ ] **Runtime requirement**: `TELNYX_API_KEY` and `TELNYX_PHONE_NUMBER` env vars must be configured (Telnyx hook at `src/app/api/hooks/send-sms/route.ts` is already implemented).
- [ ] **Supabase dashboard**: Set the SMS webhook URL to `https://your-domain.com/api/hooks/send-sms` in Supabase Auth settings.

### 2. Supabase Credentials ✅ FIXED
- [x] Removed placeholder fallbacks in `src/lib/supabase.ts` — now throws at startup if env vars are not set.
- [x] Added same guard to `src/app/api/auth/callback/route.ts`.
- [x] Added runtime validation with clear error messages.
- [x] **Linked remote project** via `supabase link --project-ref odhaoehucfyrqhanthyq`.
- [x] **Synced migration history** — all 5 migrations (waitlist, referrals, modules_marketplace, users, + remote 20260406180000) are applied and matched.
- [x] **Verified `user_profiles` table** exists and accessible on remote.
- [x] **Verified Telnyx SMS** — API key works, `+19492847328` is active with messaging enabled.
- [ ] **Supabase dashboard (manual step)**: In Supabase Dashboard → Auth → SMS → configure webhook URL to `https://threatcrush.com/api/hooks/send-sms` with secret `ad6a68662e81fba4c6beb8f7674a15cbdc28946eec8066397bcaf36599f7ceda`. Enable phone provider "Twilio Verify / custom provider" pointing to the webhook.

### 3. CLI Commands — All Gated
All commands below currently just prompt for email and say "Coming soon — ThreatCrush is in private beta." (`cli/src/index.ts`):
- [ ] `threatcrush monitor`
- [ ] `threatcrush tui`
- [ ] `threatcrush init`
- [ ] `threatcrush scan`
- [ ] `threatcrush pentest`
- [ ] `threatcrush status`
- [ ] `threatcrush start`
- [ ] `threatcrush stop`
- [ ] `threatcrush logs`
- [ ] `threatcrush activate`
- [ ] `threatcrush modules` (gated at line 283)
- [ ] `threatcrush store` (gated at line 290)
- [ ] `threatcrush store search` (gated at line 296)
- [ ] `threatcrush update --modules` — says "Module updates coming soon" (line 235)

### 4. TUI Dashboard — Not Implemented
- [ ] Create `cli/src/tui/dashboard.js` — referenced by `cli/src/commands/monitor.ts:31` but the entire `cli/src/tui/` directory does not exist.

### 5. Module Marketplace — Not Functional
- [ ] `threatcrush modules install` — says "Module marketplace is not yet available" (`cli/src/commands/modules.ts:57-60`).
- [ ] Local module install (`./path`) — says "This feature is coming soon" (`cli/src/commands/modules.ts:54`).
- [ ] Build real backend for module install/purchase flows (store pages exist but are UI-only).

### 6. Module SDK — Not Published
- [ ] Publish `@threatcrush/sdk` package. The `boilerplates/module-example/src/index.ts` defines its own `ModuleContext` and `EventPayload` interfaces instead of importing from `@threatcrush/sdk`.

### 7. Desktop Release Pipeline — Failing
- [ ] Fix packaging configuration in GitHub Actions desktop release workflow (fails on all matrix targets: Linux, macOS, Windows).
- [ ] Configure macOS signing/notarization secrets: `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `KEYCHAIN_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`.
- [ ] Configure Windows signing secrets: `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD`.
- [ ] Verify GitHub Releases are created properly on tag pushes.
- [ ] Generate and attach checksums.
- [ ] Decide how website download buttons should work (direct GitHub release assets vs. first-party downloads page).
- [ ] Update `/docs/releases` with confirmed artifact names.
- [ ] Update homepage/download section only after at least one successful release.

### 8. Desktop App — Placeholder IPC
- [ ] `connectDaemon()` in `desktop/src/preload/index.ts` is a placeholder — always returns `Promise.resolve(false)`. No real IPC with the daemon is implemented.

---

## 🟡 Significant Gaps

### 9. Mobile App — Not Shipped
- [ ] Run `eas login` (Expo auth not completed).
- [ ] Create or link Expo project under intended identity (`eas init`).
- [ ] Configure `EXPO_TOKEN` GitHub secret.
- [ ] Produce at least one successful preview build in EAS.
- [ ] Decide on production build + auto-submit path.
- [ ] Confirm Apple App Store Connect and Google Play setup.
- [ ] Update site copy once real artifacts exist.
- [ ] Add mobile release notes to `/docs/releases`.
- [ ] Replace minimal sanity screen in `mobile/app/index.tsx` with real functionality.
- [ ] Integrate E2E encryption (`mobile/src/lib/crypto.ts`) into real communication flow (currently described as "stubs").
- [ ] Replace hardcoded demo data in `mobile/src/stores/events.ts` with real API calls.

### 10. Browser Extension — Demo Data Only
- [ ] Replace `checkForEvents()` demo data with real API calls (`extension/src/background/index.js:58-59`).
- [ ] Implement real `scanUrl()` — currently always returns `{ status: 'secure' }` (line 130).
- [ ] Show scan results in popup UI instead of just logging to console (`extension/src/popup/components/QuickActions.jsx:19`).
- [ ] Replace demo data in `fetchStats()` with real API calls (`extension/src/store/events.js:4`). Uncomment real `chrome.runtime.sendMessage` call (line 50).
- [ ] Submit to Chrome Web Store, Firefox Add-ons, Safari (all "coming soon" per README).

### 11. Usage / Billing API — Demo Data Fallback
- [ ] Connect real CoinPayPortal API (requires `COINPAYPORTAL_API_KEY` and `COINPAYPORTAL_BUSINESS_ID` env vars).
- [ ] Implement `daily_spend` and `module_breakdown` arrays (currently returned empty even when API is connected, `src/app/api/usage/route.ts:186-187`).
- [ ] Implement real top-up flow (currently shows alert: "Demo mode: Top-up simulated!" at `src/app/usage/usage-content.tsx:86`).

### 12. Waitlist API — Payment Methods Not Implemented
- [ ] Implement crypto payments — currently says "Crypto payments coming soon" (`src/app/api/waitlist/route.ts:142`).
- [ ] Implement card payments — currently says "Card payments coming soon" (`src/app/api/waitlist/route.ts:245`).
- [ ] Implement payment method selection in UI (`src/components/WaitlistModal.tsx:116`).

### 13. Homepage — Features Marked "Coming Soon"
- [ ] Implement three "Coming soon" feature sections on homepage (`src/app/page.tsx:601, 624, 650`).

### 14. Package Manager Submissions — Placeholder Hashes
- [ ] Replace `SHA256_PLACEHOLDER` in Homebrew submission (`scripts/lib/package-managers/homebrew.ts:58-59`).
- [ ] Replace `SHA256_PLACEHOLDER` in Winget submission (`scripts/lib/package-managers/winget.ts:41`).
- [ ] Replace `SHA256_PLACEHOLDER` in Scoop submission (`scripts/lib/package-managers/scoop.ts:69`).

---

## 🔵 Future / Nice-to-Have

### 15. PRD Roadmap — Phase 1 (MVP)
- [ ] CLI scaffold with `init`, `monitor`, `status` commands (exists but gated).
- [ ] Core module: `log-watcher` (partially implemented in CLI monitor command).
- [ ] Core module: `ssh-guard` (partially implemented in CLI monitor command).
- [ ] Alert system (webhook).
- [ ] systemd unit file.

### 16. PRD Roadmap — Phase 2 (Beta)
- [ ] Core module: `network-monitor` (pcap-based).
- [ ] Core module: `code-scanner` (CLI scan command exists but is gated).
- [ ] Core module: `pentest-engine`.
- [ ] Module store on threatcrush.com (store pages exist but are UI-only).
- [ ] `threatcrush modules install/publish` commands (gated).
- [ ] License activation (gated).

### 17. PRD Roadmap — Phase 3 (Launch)
- [ ] Core module: `dns-monitor`.
- [ ] Core module: `firewall-rules`.
- [ ] Dashboard web UI.
- [ ] Cloud sync.
- [ ] Enterprise features.

### 18. Docker / NPM / CI Workflows
- [ ] Retest Docker publish workflow (had issues with Docker Hub auth; needs retest after GHCR-only fallback fix).
- [ ] Confirm `npm-publish.yml` workflow works with real secrets.
- [ ] Confirm `docker-publish.yml` workflow works with real secrets.
- [ ] Confirm `submit-packages.yml` workflow works with real secrets.

### 19. Hardware Appliance — Future Plans Only
- The entire "ThreatCrush Box" hardware appliance line (Stick, Mini, Rack) is a future plan per `docs/FUTURE_PLANS.md`. Timeline starts Q3 2026 for software MVP and extends to 2028 for enterprise hardware. No action needed now.

---

## Quick Reference

| Category | Key Files |
|---|---|
| Phone verification | `src/app/api/auth/verify-phone/route.ts` |
| Supabase config | `src/lib/supabase.ts` |
| CLI commands | `cli/src/index.ts`, `cli/src/commands/*.ts` |
| TUI dashboard | `cli/src/tui/` (missing entirely) |
| Module marketplace | `cli/src/commands/modules.ts` |
| Desktop app | `desktop/src/preload/index.ts`, `.github/workflows/desktop-release.yml` |
| Mobile app | `mobile/app/index.tsx`, `mobile/src/stores/events.ts`, `mobile/src/lib/crypto.ts` |
| Browser extension | `extension/src/background/index.js`, `extension/src/store/events.js` |
| Usage/billing | `src/app/api/usage/route.ts`, `src/app/usage/usage-content.tsx` |
| Waitlist/payments | `src/app/api/waitlist/route.ts`, `src/components/WaitlistModal.tsx` |
| Homepage | `src/app/page.tsx` |
| Package managers | `scripts/lib/package-managers/homebrew.ts`, `winget.ts`, `scoop.ts` |
