<p align="center">
  <a href="https://threatcrush.com"><img src="https://threatcrush.com/logo.svg" alt="ThreatCrush" width="120" /></a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@profullstack/threatcrush"><img src="https://img.shields.io/npm/v/@profullstack/threatcrush?color=00ff41&style=flat-square&label=version" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/@profullstack/threatcrush"><img src="https://img.shields.io/npm/dm/@profullstack/threatcrush?color=00ff41&style=flat-square&label=downloads" alt="downloads" /></a>
  <a href="https://github.com/profullstack/threatcrush"><img src="https://img.shields.io/github/license/profullstack/threatcrush?color=00ff41&style=flat-square" alt="license" /></a>
  <a href="https://github.com/profullstack/threatcrush"><img src="https://img.shields.io/github/stars/profullstack/threatcrush?color=00ff41&style=flat-square" alt="stars" /></a>
  <a href="https://github.com/profullstack/threatcrush"><img src="https://img.shields.io/badge/github-profullstack%2Fthreatcrush-00ff41?style=flat-square&logo=github" alt="github" /></a>
  <img src="https://img.shields.io/node/v/@profullstack/threatcrush?color=00ff41&style=flat-square" alt="node" />
  <img src="https://img.shields.io/badge/platform-linux-00ff41?style=flat-square" alt="platform" />
</p>

<h1 align="center">
  <br>
  ThreatCrush
  <br>
</h1>

<h4 align="center">All-in-one security agent — monitor, detect, scan, and protect servers in real-time.</h4>

<p align="center">
  <img src="https://threatcrush.com/images/gallery-cli.png" alt="ThreatCrush CLI" width="48%" />
  <img src="https://threatcrush.com/images/gallery-tui.png" alt="ThreatCrush TUI" width="48%" />
</p>
<p align="center">
  <img src="https://threatcrush.com/images/gallery-desktop.png" alt="ThreatCrush Desktop" width="60%" />
</p>
<p align="center">
  <img src="https://threatcrush.com/images/gallery-mobile.png" alt="ThreatCrush Mobile" width="30%" />
</p>

<p align="center">
  <a href="https://threatcrush.com">Website</a> •
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#features">Features</a> •
  <a href="#modules">Modules</a> •
  <a href="https://github.com/profullstack/threatcrush">GitHub</a>
</p>

---

ThreatCrush is a security daemon that runs on your server, monitoring **every connection on every port**. It detects live attacks, scans your codebase, pentests your APIs, and alerts you in real-time.

```
$ threatcrush monitor

  [12:03:41] ✓ Monitoring all ports · nginx · sshd · postgres
  [12:03:42] ✓ Loaded 1,247 attack signatures
  [12:03:45] ⚠ SQLi attempt — :443 185.43.21.8 → /api/users?id=1 OR 1=1
  [12:03:47] ✗ SSH brute force — :22 91.232.105.3 → 47 failed attempts
  [12:03:50] ⚠ Port scan — 45.33.32.156 scanning :21-:8080 (SYN flood)
  [12:03:52] ⚠ DNS tunneling — :53 suspicious TXT queries from 103.44.8.2
  [12:04:01] ✓ 3,891 connections analyzed · 4 threats · 1 blocked
```

## Install

**Preferred install:**

```bash
curl -fsSL https://threatcrush.com/install.sh | sh
```

The installer detects whether the machine is a server or desktop, uses your existing package manager when available, and can bootstrap Node.js with `mise` on bare machines.

- **Linux server** → installs the CLI
- **Linux desktop** → installs the CLI + desktop app
- **Windows desktop** → installs the desktop app to connect to a ThreatCrush server elsewhere
- **macOS desktop** → desktop-oriented install for connecting to a ThreatCrush server

After install, the supported lifecycle commands are:

```bash
threatcrush update   # upgrades the installed bundle
threatcrush remove   # removes the installed bundle
```

Manual package-manager installs still work:

```bash
npm i -g @profullstack/threatcrush
pnpm add -g @profullstack/threatcrush
yarn global add @profullstack/threatcrush
bun add -g @profullstack/threatcrush
```

## Usage

```bash
threatcrush              # Get started
threatcrush monitor      # Real-time security monitoring (all ports)
threatcrush tui          # Interactive dashboard (htop for security)
threatcrush scan ./src   # Scan code for vulnerabilities & secrets
threatcrush pentest URL  # Penetration test a URL/API
threatcrush init         # Auto-detect services, generate config
threatcrush status       # Show daemon status & loaded modules
threatcrush modules      # Manage security modules
threatcrush store        # Browse the module marketplace
threatcrush update       # Upgrade the CLI using the supported path
```

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Live Attack Detection** | Monitors all inbound connections on every port. Detects SQLi, XSS, brute force, SSH attacks, port scans, DNS tunneling. |
| 🛡️ **Code Security Scanner** | Scan your codebase for vulnerabilities, hardcoded secrets, and misconfigurations. |
| 💥 **Pentest Engine** | Automated penetration testing on your URLs and APIs. |
| 🔀 **Network Monitor** | Watches all TCP/UDP traffic across every port — HTTP, SSH, DNS, FTP, databases. |
| 🔔 **Real-time Alerts** | Slack, email, webhook notifications the instant a threat is detected. |
| ⚙️ **systemd Daemon** | Runs as a background service on your server. Auto-starts on boot, monitors 24/7. |
| 📊 **TUI Dashboard** | Interactive terminal dashboard — htop for security. |

## Modules

ThreatCrush uses a pluggable module system. Install from the marketplace or build your own:

```bash
threatcrush modules list                # List installed
threatcrush modules install ssh-guard   # Install a module
threatcrush modules install docker-monitor
threatcrush store search "firewall"     # Search marketplace
threatcrush store publish ./my-module   # Publish your own
```

### Core Modules (included)

| Module | What it monitors |
|--------|-----------------|
| `network-monitor` | All TCP/UDP traffic, port scans, SYN floods |
| `log-watcher` | nginx, Apache, syslog, journald |
| `ssh-guard` | Failed logins, brute force, tunneling |
| `code-scanner` | Vulnerabilities, secrets, dependency CVEs |
| `pentest-engine` | SQLi, XSS, SSRF, API fuzzing |
| `dns-monitor` | DNS tunneling, DGA detection |
| `firewall-rules` | Auto-blocks via iptables/nftables |
| `alert-system` | Slack, Discord, email, webhook, PagerDuty |

### Community Modules

Build and sell your own modules on the ThreatCrush marketplace:
- `docker-monitor` — Container escape detection
- `k8s-watcher` — Kubernetes cluster security
- `honeypot` — Deploy decoy services
- `geo-blocker` — Block traffic by country/ASN
- `compliance-reporter` — SOC2, HIPAA, PCI-DSS reports

## Configuration

```bash
threatcrush init    # Auto-detect & generate config
```

Config lives at `/etc/threatcrush/threatcrushd.conf` with module configs in `/etc/threatcrush/threatcrushd.conf.d/`.

## Pricing

| Tier | Price |
|------|-------|
| **Lifetime Access** | $499 one-time |
| **With Referral** | Friend pays $399 · You earn $100 cash per referral |

Pay once, access forever. All core modules, CLI, daemon, API, and lifetime updates included.

👉 [Get lifetime access at threatcrush.com](https://threatcrush.com)

## Browser Extension

Monitor security from your browser:

- **Chrome** — Chrome Web Store (coming soon)
- **Firefox** — Firefox Add-ons (coming soon)
- **Safari** — Coming soon

Features: scan any site, real-time alerts, security headers check, dashboard popup.

## Links

- 🌐 **Website:** [threatcrush.com](https://threatcrush.com)
- 📦 **npm:** [@profullstack/threatcrush](https://www.npmjs.com/package/@profullstack/threatcrush)
- 🐙 **GitHub:** [profullstack/threatcrush](https://github.com/profullstack/threatcrush)
- 🐛 **Issues:** [GitHub Issues](https://github.com/profullstack/threatcrush/issues)

## License

MIT © [Profullstack, Inc.](https://profullstack.com)
