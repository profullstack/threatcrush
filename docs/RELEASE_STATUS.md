# Release Status

Updated: 2026-04-05 UTC

## What is definitely active
- `PR Checks`
  - file: `.github/workflows/pr-checks.yml`
  - used for routine branch/PR validation

## What exists in repo but still needs real-world confirmation
- `Desktop Release`
  - file: `.github/workflows/desktop-release.yml`
- `Publish CLI to npm`
  - file: `.github/workflows/npm-publish.yml`
- `Publish Docker Image`
  - file: `.github/workflows/docker-publish.yml`
- `Submit to Package Managers`
  - file: `.github/workflows/submit-packages.yml`
- `Mobile Release`
  - file: `.github/workflows/mobile-release.yml`

## Current blockers / unknowns
- Expo / EAS login not completed locally during this session
- Expo project not yet linked under the intended separate project identity
- Release secrets/signing credentials not confirmed in this session
- Desktop Release workflow is active but currently fails in `Package desktop app`
- Docker Publish workflow was active but attempted Docker Hub pushes even when Docker Hub auth was not available/usable; workflow now needs retest after GHCR-only fallback fix
- Website still needs to stay honest about which downloadable artifacts truly exist

## Supporting docs
- `docs/MOBILE_RELEASE_TODO.md`
- `docs/DESKTOP_RELEASE_TODO.md`
- `mobile/EXPO_SETUP.md`
- `src/app/docs/releases/page.tsx`

## Short-term priorities
1. Finish Expo/EAS project setup and run a preview mobile build.
2. Verify desktop release workflow by actually running it.
3. Confirm npm/docker/package-manager workflows with real secrets or document what is missing.
4. Align website download/install messaging with only the release surfaces that are proven.
