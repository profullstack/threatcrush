# Desktop Release TODO

Status: checked 2026-09-25 against GitHub Actions and the v0.13.7 release.

## Current reality

- `.github/workflows/desktop-release.yml` runs on every `v*` tag and publishes a
  GitHub Release. It has succeeded for every tag from v0.13.2 to v0.13.7
  (v0.13.0 and v0.13.1 failed on `win-x64`, fixed by installing only the
  desktop workspace; see the comment above "Install dependencies").
- The v0.13.7 release carries (desktop package version 0.7.7; the desktop app is
  versioned separately from the CLI tag):

  | Asset | Platform |
  |---|---|
  | `threatcrush-desktop-0.7.7-arm64.dmg` / `-arm64.zip` | macOS, Apple silicon |
  | `threatcrush-desktop-0.7.7-x64.dmg` / `-x64.zip` | macOS, Intel |
  | `threatcrush-desktop-0.7.7-x64-setup.exe` | Windows x64 (NSIS) |
  | `threatcrush-desktop-0.7.7-x86_64.AppImage` | Linux x64 |
  | `threatcrush-desktop-0.7.7-amd64.deb` | Debian/Ubuntu x64 |
  | `SHA256SUMS.txt` | checksums of all of the above |

- **Signing: none.** The repo has no Apple or Windows signing secrets, so the
  macOS and Windows builds are unsigned and macOS builds are not notarized. The
  workflow now turns signing on by itself once the secrets below exist.
- The same workflow packages (unsigned, never published) on pull requests that touch
  `apps/desktop/**`, `scripts/desktop-signing-env.sh` or the workflow itself.
- The v0.13.7 Linux artifacts were launched headless (Xvfb) in clean
  containers. As published, the `.deb` did **not** declare `libgbm1` or ALSA,
  so on a minimal install both it and the AppImage died with
  `libgbm.so.1: cannot open shared object file`. With those two libraries
  present both start, keep running and open the 1400×900 "ThreatCrush" window.
  `deb.depends` in `apps/desktop/electron-builder.yml` now declares `libgbm1`
  and `libasound2t64 | libasound2`; the rebuilt `.deb` installs and starts on
  a bare `debian:bookworm`, `debian:trixie` and `ubuntu:24.04`. Desktop
  Ubuntu/Debian installs already have both libraries, which is why nobody hit
  this.
- Not built: Linux arm64, Windows arm64, rpm.

## Signing secrets (blocked on accounts only the owner can open)

Add them under **Settings → Secrets and variables → Actions**. Nothing else
needs to change; `scripts/desktop-signing-env.sh` exports whatever is set and
the job summary says which of signing/notarization ran.

### macOS: signing (both required)

| Secret | Value |
|---|---|
| `APPLE_CERTIFICATE` | `base64 -i developer-id.p12` of a **Developer ID Application** certificate exported with its private key |
| `APPLE_CERTIFICATE_PASSWORD` | the password chosen when exporting that `.p12` |

How to get it: join the Apple Developer Program (USD 99/year,
developer.apple.com/programs; an organization needs a D-U-N-S number). Then, as
the Account Holder, go to Certificates, Identifiers & Profiles → Certificates →
**+** → *Developer ID Application*, upload a CSR made in Keychain Access
(Certificate Assistant → Request a Certificate From a Certificate Authority),
download the certificate, double-click it, and export it together with its
private key from Keychain Access as a `.p12`.

### macOS: notarization (one group; runs only when the app is signed)

The App Store Connect API key is what electron-builder recommends for CI: it
does not expire and needs no 2FA.

| Secret | Value |
|---|---|
| `APPLE_API_KEY` | full text of `AuthKey_<KEY_ID>.p8` (the workflow writes it to a file) |
| `APPLE_API_KEY_ID` | the 10-character Key ID |
| `APPLE_API_ISSUER` | the Issuer ID (UUID) shown above the keys list |

How to get it: App Store Connect → Users and Access → Integrations → App Store
Connect API → Team Keys → **+**, role *Developer*. The `.p8` can be downloaded
once only.

Alternative group (used instead if `APPLE_ID` is set):

| Secret | Value |
|---|---|
| `APPLE_ID` | Apple ID email of a team member |
| `APPLE_APP_SPECIFIC_PASSWORD` | from account.apple.com → Sign-In and Security → App-Specific Passwords |
| `APPLE_TEAM_ID` | 10-character Team ID (developer.apple.com → Account → Membership details) |

If `APPLE_CERTIFICATE` is set without either group, the build is signed but
not notarized and the workflow raises a warning, because Gatekeeper still
blocks such an app. A partly filled group fails the build.

### Windows: signing (both required)

| Secret | Value |
|---|---|
| `WINDOWS_CERTIFICATE` | `base64 -w0 codesign.pfx` of an Authenticode code-signing certificate with its private key |
| `WINDOWS_CERTIFICATE_PASSWORD` | the `.pfx` password |

How to get it: buy an OV or EV code-signing certificate from a CA (DigiCert,
Sectigo, SSL.com, …). Caveat: since June 2023 CAs must issue these keys on
hardware (USB token or cloud HSM), and most will not hand out an exportable
`.pfx`. The secrets above work only with a CA that still delivers a `.pfx`.
If the key lives in an HSM, the realistic CI route is Azure Trusted Signing,
which electron-builder 25 supports through `win.azureSignOptions` plus
`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`; that needs a
small workflow change and is not wired up yet.

## Remaining work

- Get the signing credentials above (owner only).
- After the first signed build, check on a real Mac:
  `spctl --assess --type exec -vv ThreatCrush.app` should report
  `source=Notarized Developer ID`, and `xcrun stapler validate` should pass.
- Decide whether to add Linux arm64 to the matrix.
- Auto-update feed (`publish: []` today).
