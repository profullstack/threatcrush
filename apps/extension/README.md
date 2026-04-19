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

## Features

- Scan any site (security headers, mixed content, basic checks)
- Real-time alert popup when a ThreatCrush server emits a critical event
- Dashboard popup — recent events + module status

## Structure

```
apps/extension/
├── manifest.json         MV3 manifest (per-browser variants in src/manifests/)
├── src/
│   ├── background/       Service worker
│   ├── popup/            React popup UI
│   ├── options/          React options page
│   ├── content/          Content scripts
│   └── store/            Zustand stores (shared)
└── scripts/build.js      Per-browser packager
```

## Store submission (post-launch)

Each store has its own review process:
- **Chrome Web Store** — requires dev fee, screenshots, privacy policy, scope justification
- **Firefox AMO** — free; source review if minified
- **Safari** — App Store Connect, Apple Developer membership required

None submitted yet.
