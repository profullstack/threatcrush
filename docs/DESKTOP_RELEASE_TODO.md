# Desktop Release TODO

Status: stubbed / documented on 2026-04-05

## Goal
Ship real downloadable desktop builds for ThreatCrush with a release flow that matches what the website promises.

## Current reality
- `desktop/` is a real Electron app.
- `.github/workflows/desktop-release.yml` exists.
- Desktop workflow builds are defined for macOS, Windows, and Linux.
- Actual GitHub Actions evidence from release tag runs shows the workflow is active but failing in the `Package desktop app` step on every matrix target.
- It is not yet confirmed from this session that signing/notarization/release secrets are configured and working in practice.
- Site copy should not overstate desktop availability until artifacts are confirmed.

## Existing workflow
- `.github/workflows/desktop-release.yml`

## Known failure from GitHub Actions
Recent tag-triggered runs (for example `v0.1.14`) show:
- workflow is registered and active
- matrix jobs start correctly
- `Build desktop app` succeeds
- `Package desktop app` fails on Linux, macOS, and Windows

This means the problem is not workflow registration; it is packaging configuration/runtime behavior in the release step.

## Required setup
### 1) Confirm build matrix works in practice
- Trigger manual desktop release workflow.
- Verify artifacts are produced for:
  - macOS arm64
  - macOS x64
  - Windows x64
  - Linux x64
  - Linux arm64

### 2) Signing / notarization
#### macOS
- Confirm these secrets are set and valid:
  - `APPLE_CERTIFICATE`
  - `APPLE_CERTIFICATE_PASSWORD`
  - `KEYCHAIN_PASSWORD`
  - `APPLE_ID`
  - `APPLE_APP_SPECIFIC_PASSWORD`
  - `APPLE_TEAM_ID`

#### Windows
- Confirm these secrets are set and valid:
  - `WINDOWS_CERTIFICATE`
  - `WINDOWS_CERTIFICATE_PASSWORD`

### 3) Release verification
- Confirm GitHub Releases are created properly on tag pushes.
- Confirm checksums are generated and attached.
- Confirm artifact names are sensible and stable enough for docs/download buttons.

### 4) Download UX
- Decide how website download buttons should work:
  - point directly to GitHub release assets, or
  - route through a first-party downloads page

## Docs / site TODO
- Update `/docs/releases` with confirmed artifact names and actual tested platforms.
- Update homepage/download section only after at least one successful release is verified.
- Remove vague availability claims if the release pipeline is still unproven.

## Definition of done
- workflow runs successfully end-to-end
- signed/notarized artifacts are produced where intended
- GitHub Release contains the expected downloadable assets
- site/docs point at real release outputs
