# ThreatCrush Browser Extension

MV3 extension built with Vite + React 19 + Tailwind. **Status:** dev preview. Sideload-from-source works today; store submissions happen post-launch.

## Dev

```bash
# from repo root
pnpm install
cd apps/extension
pnpm dev                   # vite dev server for popup/options
```

## Build

Per-browser builds via `scripts/build.js`:

```bash
pnpm build                 # → dist/chrome, dist/firefox, dist/safari
node scripts/build.js chrome
node scripts/build.js firefox
node scripts/build.js safari
node scripts/build.js all
```

## Sideload (while stores are pending)

**Chrome / Edge:**
1. `pnpm build` and open `chrome://extensions`
2. Enable *Developer mode*
3. *Load unpacked* → select `apps/extension/dist/chrome/`

**Firefox:**
1. Open `about:debugging#/runtime/this-firefox`
2. *Load Temporary Add-on* → select `apps/extension/dist/firefox/manifest.json`

**Safari:**
Requires Xcode to convert to a Safari Web Extension bundle. See Apple's [Safari Web Extensions docs](https://developer.apple.com/documentation/safariservices/safari_web_extensions).

## Page checks

The popup's **This page** tab checks the site in the active tab. All of it runs in your browser.

| Check | Source | Pass / warn / fail |
| --- | --- | --- |
| HTTPS | tab URL | fail on plain HTTP (warn on loopback) |
| Strict-Transport-Security | response headers | fail if missing, `max-age=0` or unparseable; warn under 180 days; n/a over HTTP |
| Content-Security-Policy | headers, then `<meta>` | fail on script `'unsafe-inline'` (without nonce/hash), `*`, `https:`, `data:`; warn on `'unsafe-eval'`, report-only, or missing |
| Clickjacking | CSP `frame-ancestors`, else `X-Frame-Options` | fail if `frame-ancestors` allows any origin; warn if missing or `ALLOW-FROM` |
| X-Content-Type-Options | headers | warn unless `nosniff` |
| Referrer-Policy | headers, `<meta name=referrer>` | fail on `unsafe-url`; warn on `no-referrer-when-downgrade` or missing |
| Permissions-Policy | headers | warn if missing or only legacy `Feature-Policy` |
| Mixed content | Resource Timing + DOM | fail on http:// scripts, frames, styles, fetches; warn on http:// images/media |
| Forms | DOM | fail on a password field over HTTP or an HTTPS page posting to http:// |
| Cookies | `chrome.cookies` | for likely session cookies (by name): fail on no `Secure` over HTTPS; warn on no `HttpOnly` (CSRF cookies exempt) or `SameSite` None/unset. Names only, never values |

The toolbar badge is set per tab: the number of failures (red), else warnings (amber), else ✓. It is updated as each page finishes loading (toggle in Options → Page checks) and whenever the popup opens.

The checks live in `src/lib/page-checks.js` as pure functions and are unit-tested in `__tests__/page-checks.test.js`. `src/background/page-checks.js` collects the inputs.

## Privacy

Nothing about the pages you visit leaves the browser. The extension keeps each tab's security headers in `storage.session` (cleared when the tab closes or the browser exits), reads cookie names and flags but never values, and reads form targets and subresource URLs from the page.

The only exception is the **Scan with ThreatCrush** button. Clicking it sends the page's origin and path (query string and fragment removed) to `POST /api/scan` on the ThreatCrush web app, which fetches that URL server-side and grades its headers. The popup shows the exact URL before you click. The same statement is on the options page.

## Permissions

| Permission | Why | Install warning (Chrome) |
| --- | --- | --- |
| `activeTab` | Read the tab's URL and inspect its DOM when you click the toolbar button | none |
| `scripting` | Run the DOM collector (`src/lib/collect-page.js`) in the page | none |
| `webRequest` | Observe (never block or modify) main-frame response headers | none on its own |
| `cookies` | Read cookie flags for the site | none on its own |
| `storage`, `alarms`, `notifications` | Settings, account polling, alerts | none |
| `optional_host_permissions: http://*/*, https://*/*` | Needed for `webRequest` and `cookies` to see a site, and for the per-page badge. **Requested at first use** from the popup's "Enable page checks" button or Options → Page checks, and revocable there | shown only when requested |

Header capture has to be in place before the page loads, which is why the site access is broad rather than per-click: `activeTab` is granted after the page has already loaded, too late to observe its response headers. Without site access, the HTTPS, forms and mixed-content checks still run when you open the popup; headers and cookies show as Unknown. After granting access, reload the page once (the popup offers a button) so its headers are captured.

### Firefox differences

- Host permissions in MV3 are always user-controlled; `optional_host_permissions` needs Firefox 128+ (the manifest requires 142+).
- The background is an event page (`background.scripts`), not a service worker. `webRequest` listeners are registered at top level, so they wake it.
- `webRequest.onHeadersReceived` with `responseHeaders` works the same. Firefox MV3 still allows blocking listeners; this extension only observes.
- `permissions.request()` must be called synchronously from the click handler. Firefox may close the popup while its permission prompt is open; reopen it afterwards.
- With first-party isolation on, `cookies.getAll` needs `firstPartyDomain`; the extension retries with `firstPartyDomain: null`.
- `data_collection_permissions` stays `none`: the scan button is a user-initiated, clearly labelled transmission of the current page URL, which AMO's add-on policy (§6.2.2.2) treats as implied consent.

### Safari

Safari's `webRequest` support is limited, so header checks may show Unknown there. Not tested; Safari needs an Xcode wrapper project and an Apple developer account.

## Account features

The **Account** tab signs in with Supabase and shows usage and alerts. The build reads `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` (and `NEXT_PUBLIC_APP_URL`, default `https://threatcrush.com`) from the environment or `apps/.env*`. Without the Supabase values, sign-in reports that it isn't configured; page checks still work.

## Structure

```
apps/extension/
├── src/
│   ├── manifest.{chrome,firefox,safari}.json
│   ├── background/       Service worker: account polling, page checks, badge
│   ├── lib/              API client, Supabase client, page checks, DOM collector
│   ├── popup/            React popup UI (This page / Account)
│   ├── options/          React options page
│   └── store/            Zustand stores
└── scripts/build.js      Per-browser packager
```

## Store submission (post-launch)

Each store has its own review process:
- **Chrome Web Store** — needs a developer account (one-time fee), screenshots, a privacy policy, and a justification for the optional `http://*/*` / `https://*/*` host access (the Privacy and Permissions sections above are the basis)
- **Firefox AMO** — needs an AMO account and API key/secret for `web-ext sign`; source review if minified
- **Safari** — needs an Apple Developer membership and an Xcode Safari Web Extension wrapper project, signed and submitted through App Store Connect

None submitted yet; all three are blocked on those accounts.
