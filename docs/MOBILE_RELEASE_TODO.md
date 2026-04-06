# Mobile Release TODO

Status: stubbed / documented on 2026-04-05

## Goal
Ship real native mobile builds for ThreatCrush using Expo / EAS under a separate Expo project.

## Current reality
- `mobile/` is already an Expo app.
- `mobile/eas.json` exists.
- `.github/workflows/mobile-release.yml` now exists.
- Local machine is **not logged into EAS**, so project linking/build submission was not completed yet.
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
