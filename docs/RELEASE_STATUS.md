# Release Status

Updated: 2026-09-25, from `gh run list`, `gh release view v0.13.7`, npm and
GHCR. Every `v*` tag (cut by `scripts/release.mjs`) fires the release
workflows below.

## Workflows

| Workflow | File | State | Evidence / what it produces |
|---|---|---|---|
| PR Checks | `pr-checks.yml` | green | Lint & Build plus the web, CLI, scan, module, desktop and extension vitest suites and the extension build, on PRs and master. |
| Publish CLI and SDK to npm | `npm-publish.yml` | CLI green; SDK job not yet run | `@profullstack/threatcrush@0.13.7` is on npm. The `publish-sdk` job (publishes `apps/sdk` as `@threatcrush/sdk` on tags) has not run yet; `@threatcrush/sdk` is not on npm, and the `@threatcrush` npm scope and `NPM_TOKEN` rights for it are unconfirmed. |
| Desktop Release | `desktop-release.yml` | green, unsigned | Succeeded for v0.13.2–v0.13.7. The v0.13.7 GitHub Release has macOS arm64/x64 `.dmg` + `.zip`, Windows x64 `-setup.exe`, Linux x64 `.AppImage` + `.deb`, `SHA256SUMS.txt`. No signing secrets exist, so macOS/Windows builds are unsigned and not notarized; signing switches on when the secrets are added (see `DESKTOP_RELEASE_TODO.md`). Linux artifacts smoke-tested under Xvfb in `debian:bookworm`. |
| Publish Docker Image | `docker-publish.yml` | green, but the image is private | Pushes `ghcr.io/profullstack/threatcrush:{latest,0.13.7}` (no `DOCKER_USERNAME`, so no Docker Hub). An anonymous pull gets `401 authentication required`: the GHCR package is not public. |
| Mobile Release | `mobile-release.yml` | green, Android only | On tags: EAS `production` build for **Android** only (AAB on expo.dev, not submitted to Google Play). iOS builds and store submission run only via manual dispatch and have no recorded success. |
| Submit to Package Managers | `submit-packages.yml` | not running | Last run 2026-08-08 failed ("Release v0.5.0 not found"). It triggers on `release: published`, but Desktop Release publishes with `GITHUB_TOKEN` (no `PKG_SUBMIT_TOKEN` secret), and releases made with `GITHUB_TOKEN` do not trigger workflows. |

## Blocked on the owner

- Desktop signing: Apple Developer Program + `APPLE_CERTIFICATE`,
  `APPLE_CERTIFICATE_PASSWORD`, `APPLE_API_KEY`, `APPLE_API_KEY_ID`,
  `APPLE_API_ISSUER`; Windows code-signing certificate as
  `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD`. Details in
  `DESKTOP_RELEASE_TODO.md`.
- GHCR image visibility: github.com/orgs/profullstack/packages →
  `threatcrush` → Package settings → Change visibility → Public.
- Docker Hub (optional): `DOCKER_USERNAME`, `DOCKER_TOKEN`.
- Package managers: `PKG_SUBMIT_TOKEN` (a PAT, so the release event triggers
  `submit-packages.yml`) plus the per-manager secrets that workflow reads.
- Extension stores (no workflow yet, sideload only): Chrome Web Store
  developer account; Firefox AMO account + `WEB_EXT_API_KEY` /
  `WEB_EXT_API_SECRET`; Safari needs the same Apple Developer Program
  membership plus an Xcode Safari Web Extension wrapper.

## Supporting docs

- `docs/SURFACES.md`: per-interface and per-channel status
- `docs/DESKTOP_RELEASE_TODO.md`
- `docs/MOBILE_RELEASE_TODO.md`
- `apps/web/src/app/docs/releases/page.tsx` (threatcrush.com/docs/releases)
