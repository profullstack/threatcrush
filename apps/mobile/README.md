# ThreatCrush Mobile

Expo / React Native app. **Status:** deferred from v0.1.0. The Android pipeline builds cleanly on a tag push; iOS requires an Apple Developer account + one-time credentials setup.

## Dev

```bash
# from repo root
pnpm install
cd apps/mobile
pnpm expo start            # dev client (needs expo-dev-client)
```

App config lives in `app.config.ts` (code) — `app.json` is unused. `THREATCRUSH_API_URL` picks the API the app talks to (default `https://threatcrush.com`).

```bash
pnpm test         # store tests (vitest, fetch stubbed at the HTTP boundary)
pnpm typecheck
npx expo export --platform android --platform ios   # JS bundle sanity check
```

## What the app shows

Everything comes from the threatcrush.com API with the user's own session. There is no demo data.

| Tab | Source |
| --- | --- |
| Sign-in | `POST /api/auth/login`, refreshed via `POST /api/auth/refresh` |
| Threats | `GET /api/orgs/:id/detections` |
| Servers | `GET /api/orgs/:id/servers`, `GET /api/orgs/:id/remediations` |
| Scans | `GET /api/orgs/:id/runs` (scan/pentest results across the org's properties) |
| Org switcher | `GET /api/orgs`, current org from `GET/PATCH /api/auth/me` |

Detections will stay empty for most orgs until the daemon uploads them. `threatcrushd` raises alerts on the host (TUI, email, Discord, PagerDuty) but never calls `POST /api/ingest`. The empty state says so.

## Push notifications

After sign-in the Threats tab explains alerts before the OS permission prompt appears. Accepting registers the device's Expo push token for the current org with `POST /api/orgs/:id/push-subscriptions`, stored in `push_subscriptions` with `keys.provider = "expo"`. Sign-out unregisters it. The server sends a push to every registered device in the org when an alert rule routes a detection to a Push destination (Settings → Alerts).

Delivery credentials, one-time:

- **Android (FCM):** create a Firebase project for `com.threatcrush.mobile`, then upload `google-services.json` as an EAS file variable named `GOOGLE_SERVICES_JSON` (`eas env:create --name GOOGLE_SERVICES_JSON --type file --value ./google-services.json`). `app.config.ts` picks it up automatically. Upload the FCM V1 service-account key under `eas credentials → Android → Push Notifications`.
- **iOS (APNs):** `eas credentials → iOS → Push Notifications` creates the APNs key. This needs the Apple Developer account below.

## EAS Build

Uses `eas.json` profiles:

- `development` — internal dev-client builds, loads `http://localhost:3000`
- `preview` — internal testers (TestFlight / internal track)
- `production` — app store submission, auto-increments build number

```bash
eas build --profile preview --platform android
eas build --profile preview --platform ios
```

## GitHub Actions — mobile-release.yml

Triggers on every `v*` tag. Defaults to `--platform android` because iOS needs interactive credential setup (see below). Override via `workflow_dispatch` → `platform: ios | all`.

Requires these repo secrets:
- `EXPO_TOKEN` — create at https://expo.dev/settings/access-tokens
- `ENV_FILE` — full contents of `.env` dumped as a single secret

## iOS setup (one-time, interactive)

```bash
cd apps/mobile
eas credentials
```

Pick `iOS → Set up a new Distribution Certificate`. Expo stores the cert + provisioning profile in their vault; future CI builds then work non-interactively.

Requires:
- Apple Developer account ($99/yr)
- App Store Connect app record with bundle `com.threatcrush.mobile`

## Android setup

Expo can auto-generate a keystore on first build — no pre-work needed. For Play Console submission later, add a Google Service Account JSON at `apps/mobile/google-service-account.json` (gitignored) and reference it in `eas.json → submit.production.android.serviceAccountKeyPath`.

