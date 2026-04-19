# ThreatCrush Mobile

Expo / React Native app. **Status:** deferred from v0.1.0. The Android pipeline builds cleanly on a tag push; iOS requires an Apple Developer account + one-time credentials setup.

## Dev

```bash
# from repo root
pnpm install
cd apps/mobile
pnpm expo start            # dev client (needs expo-dev-client)
```

App config lives in `app.config.ts` (code) — `app.json` is unused.

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

## Not wired up yet

- Push notifications (`expo-notifications`)
- Real event stream — `src/stores/events.ts` still returns demo data
- E2E encryption integration — `src/lib/crypto.ts` is standalone
