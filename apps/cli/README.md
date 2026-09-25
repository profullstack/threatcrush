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

ThreatCrush is a security daemon that runs on your server, **reading your logs and watching inbound connections** for live attacks. It checks every nginx request against 94 OWASP CRS rules (paranoia level 1) + 1 ThreatCrush rule with CRS anomaly scoring, runs 15 detection rules over auth, web and network events, auto-bans attackers, scans your codebase, spot-checks your URLs, and alerts you in real-time.

```
$ threatcrush monitor

2026-09-25 12:03:41 [INFO]    Starting foreground monitor...
2026-09-25 12:03:41 [INFO]    Monitoring 3 log source(s):
  ● ssh-guard      → /var/log/auth.log
  ● log-watcher    → /var/log/nginx/access.log
  ● log-watcher    → /var/log/syslog

  Press Ctrl+C to stop

2026-09-25 12:03:45 [CRITICAL] [log-watcher]  Attack detected [SQLI]: GET /api/users?id=1%20UNION%20SELECT%20password%20FROM%20users (185.43.21.8)
2026-09-25 12:03:46 [CRITICAL] [log-watcher]  Attack detected [PATH_TRAVERSAL]: GET /../../etc/passwd (185.43.21.8)
2026-09-25 12:03:47 [HIGH]     [ssh-guard]    Failed SSH login for root from 91.232.105.3 (91.232.105.3)
2026-09-25 12:03:48 [HIGH]     [ssh-guard]    Invalid SSH user attempt: admin123 from 103.77.88.99 (103.77.88.99)
2026-09-25 12:03:52 [LOW]      [log-watcher]  Client error 404: GET /wp-login.php (203.0.113.9)
```

`monitor` tails your logs in the foreground. The daemon (`threatcrush start`) adds the connection poller, DNS monitor, journald, the rule engine and auto-ban.

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
threatcrush monitor      # Watch nginx, auth & syslog for attacks (foreground)
threatcrush tui          # Interactive dashboard (htop for security)
threatcrush scan ./src   # Scan code for vulnerabilities & secrets
threatcrush scan . --format sarif --output out.sarif --fail-on critical,high
threatcrush pentest URL  # Quick web security checks against a URL
threatcrush init         # Auto-detect services, generate config
threatcrush status       # Show daemon status & loaded modules
threatcrush modules      # Manage security modules
threatcrush store        # Browse the module marketplace
threatcrush update       # Upgrade the CLI using the supported path
```

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Live Attack Detection** | Tails nginx, auth, syslog and journald, and polls inbound connections to the ports you serve. Detects SQLi, XSS, path traversal, RFI, SSH brute force, port scans, SYN floods, DNS tunneling. |
| 🛡️ **Code Security Scanner** | Scan your codebase for vulnerabilities, hardcoded secrets, and misconfigurations. |
| 💥 **Pentest Checks** | `threatcrush pentest URL` spot-checks security headers, CSP, CORS, cookie flags, server banners, directory listings and error leaks, then probes for SQL errors, path traversal and unsafe HTTP methods. |
| 🔀 **Network Monitor** | Polls conntrack/`ss` every 5 s for inbound TCP connections to your listening ports. Flags port scans (10+ ports in 30 s) and SYN floods (50+ half-open from one source). No packet capture. |
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
threatcrush store publish https://github.com/you/my-module  # Publish your own
```

### Built in

| Component | What it covers |
|-----------|----------------|
| `log-watcher` | nginx access log + syslog — 94 OWASP CRS rules (PL1: SQLi, XSS, path traversal, RFI, RCE, PHP/Java injection, SSRF, scanners) + 1 ThreatCrush rule (OS files in the path) scored on every request |
| `ssh-guard` | auth.log / secure — failed logins, brute force, root logins, user enumeration |
| `user-journal` | journald — the systemd journal |
| `network-monitor` | Inbound connections to your listening ports — port scans, SYN floods |
| `dns-monitor` | Resolver logs (systemd-resolved, dnsmasq, bind, Pi-hole) — DNS tunneling, DGA detection |
| `threatcrush scan` | Vulnerabilities, secrets, dependency CVEs (OSV.dev, with `--deps`) |
| `threatcrush pentest` | Header, CORS, cookie, SQL-error, path-traversal and HTTP-method checks |
| auto-defend | Bans via fail2ban, nftables or iptables |
| alerts | Slack, Discord, email, webhook, PagerDuty |

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
