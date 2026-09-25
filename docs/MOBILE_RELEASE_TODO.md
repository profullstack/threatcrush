# Mobile Release TODO

Status: checked 2026-09-25 against GitHub Actions run history

## Goal
Ship real native mobile builds for ThreatCrush using Expo / EAS under a separate Expo project.

## Current reality
- `apps/mobile/` is an Expo app; the EAS project is `profullstack/threatcrush-mobile`
  and `EXPO_TOKEN` is set in GitHub, so steps 1–3 below are done.
- `.github/workflows/mobile-release.yml` succeeds on every `v*` tag: it runs an
  EAS `production` build for **Android only** and stores the AAB on expo.dev.
  Manual dispatches produced Android `preview` builds (2026-08-08).
- iOS has never been built, and nothing has been submitted to Google Play or
  the App Store.
- The app shows real account data from the threatcrush.com API. Push
  registration is built; delivery needs the FCM (Android) and APNs (iOS)
  credentials described in `apps/mobile/README.md`, and nothing sends pushes
  until servers upload detections.
- Site/product copy should not imply public app-store availability until real artifacts are shipping.

## Desired project identity
- Expo slug: `threatcrush-mobile`
- Display name: `ThreatCrush`
- Use a separate Expo project/account identity from any old/default project.

## Required setup
### 1) Expo auth
- Run `eas login` on the machine used for setup and testing.
- Confirm the intended Expo account/org to own the project.

### 2) Create or link project
- Run `eas init` inside `mobile/` or link to an existing separate Expo project.
- Capture:
  - `EXPO_OWNER`
  - `EXPO_PROJECT_ID`

### 3) GitHub Actions secrets
- Add `EXPO_TOKEN` to the GitHub repo secrets.
- If additional Expo submission secrets are required, document them explicitly after the first successful store submission.

### 4) Build verification
- Run preview/internal builds first:
  - Android preview
  - iOS preview
- Confirm builds complete in EAS and install successfully.

### 5) Store submission
- Decide whether production builds should:
  - only build artifacts, or
  - build + auto-submit
- Confirm Apple App Store Connect and Google Play setup is ready before enabling auto-submit by default.

## GitHub workflow
Current workflow file:
- `.github/workflows/mobile-release.yml`

Expected behavior:
- manual dispatch for preview or production
- build `android`, `ios`, or `all`
- optional auto-submit for production

## Docs / site TODO
- Update site copy once real preview or production artifacts exist.
- Add mobile build/release notes to `/docs/releases` when first successful build is confirmed.
- Remove or soften any “coming soon” or “available now” language based on what is actually true.

## Definition of done
- Expo project is linked
- `EXPO_OWNER` + `EXPO_PROJECT_ID` are known
- `EXPO_TOKEN` is configured in GitHub
- at least one successful preview build exists in EAS
- production release path is documented and repeatable
