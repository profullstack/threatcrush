#!/usr/bin/env bash
# Turns the desktop-release signing secrets into the environment electron-builder
# reads, for one matrix platform. Called by .github/workflows/desktop-release.yml;
# the secret names are documented there and in docs/DESKTOP_RELEASE_TODO.md.
#
# Only variables whose secrets are set are exported: electron-builder treats an
# empty CSC_LINK as a certificate path and aborts, so "secret missing" must mean
# "variable absent", which leaves the build unsigned exactly as before.
#
# Inputs (environment): PLATFORM (mac|win|linux), the secrets, GITHUB_ENV,
# RUNNER_TEMP, and optionally GITHUB_STEP_SUMMARY.
set -euo pipefail

: "${PLATFORM:?}" "${GITHUB_ENV:?}" "${RUNNER_TEMP:?}"

export_var() { # name value; value may not contain newlines (paths and ids only)
  printf '%s=%s\n' "$1" "$2" >>"$GITHUB_ENV"
}

summary() {
  echo "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "- $1" >>"$GITHUB_STEP_SUMMARY"; fi
}

# Writes base64 secret $1 to file $2 and prints the path.
decode_to() {
  printf '%s' "$1" | base64 --decode >"$2"
  echo "$2"
}

case "$PLATFORM" in
  mac)
    if [ -z "${APPLE_CERTIFICATE:-}" ]; then
      summary "macOS: unsigned (APPLE_CERTIFICATE not set), so not notarized either"
      exit 0
    fi
    export_var CSC_LINK "$(decode_to "$APPLE_CERTIFICATE" "$RUNNER_TEMP/developer-id.p12")"
    export_var CSC_KEY_PASSWORD "${APPLE_CERTIFICATE_PASSWORD:-}"

    # electron-builder picks the Apple ID group first, then the API key group,
    # and fails the build if either group is only partly set.
    if [ -n "${APPLE_ID:-}${APPLE_APP_SPECIFIC_PASSWORD:-}" ]; then
      export_var APPLE_ID "${APPLE_ID:-}"
      export_var APPLE_APP_SPECIFIC_PASSWORD "${APPLE_APP_SPECIFIC_PASSWORD:-}"
      export_var APPLE_TEAM_ID "${APPLE_TEAM_ID:-}"
      summary "macOS: Developer ID signing on, notarization via an Apple ID + app-specific password"
    elif [ -n "${APPLE_API_KEY:-}${APPLE_API_KEY_ID:-}${APPLE_API_ISSUER:-}" ]; then
      # electron-builder 25 hands APPLE_API_KEY to notarytool --key, which wants
      # the path of the .p8 file, not its contents.
      key_file="$RUNNER_TEMP/AuthKey_${APPLE_API_KEY_ID:-unknown}.p8"
      printf '%s\n' "${APPLE_API_KEY:-}" >"$key_file"
      if [ -n "${APPLE_API_KEY:-}" ]; then export_var APPLE_API_KEY "$key_file"; fi
      export_var APPLE_API_KEY_ID "${APPLE_API_KEY_ID:-}"
      export_var APPLE_API_ISSUER "${APPLE_API_ISSUER:-}"
      summary "macOS: Developer ID signing on, notarization via an App Store Connect API key"
    else
      # Gatekeeper still blocks a signed app that was never notarized, so make
      # the gap visible instead of shipping it silently.
      echo "::warning title=macOS build not notarized::APPLE_CERTIFICATE is set but no notarization credentials are (APPLE_API_KEY + APPLE_API_KEY_ID + APPLE_API_ISSUER, or APPLE_ID + APPLE_APP_SPECIFIC_PASSWORD + APPLE_TEAM_ID)."
      summary "macOS: Developer ID signing on, notarization OFF (no credentials)"
    fi
    ;;
  win)
    if [ -z "${WINDOWS_CERTIFICATE:-}" ]; then
      summary "Windows: unsigned (WINDOWS_CERTIFICATE not set)"
      exit 0
    fi
    export_var WIN_CSC_LINK "$(decode_to "$WINDOWS_CERTIFICATE" "$RUNNER_TEMP/authenticode.pfx")"
    export_var WIN_CSC_KEY_PASSWORD "${WINDOWS_CERTIFICATE_PASSWORD:-}"
    summary "Windows: Authenticode signing on"
    ;;
  linux)
    summary "Linux: AppImage and .deb are not signed (no signing step exists for them)"
    ;;
  *)
    echo "unknown PLATFORM: $PLATFORM" >&2
    exit 1
    ;;
esac
