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

ThreatCrush is a security daemon that runs on your server, **reading your logs and watching inbound connections** for live attacks. It checks every nginx request against 96 OWASP CRS rules (paranoia level 1) + 4 ThreatCrush rules with CRS anomaly scoring, runs 18 detection rules over auth, web and network events, auto-bans attackers, scans your codebase, spot-checks your URLs, and alerts you in real-time.

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

The CLI needs **Node.js 22.6 or newer**. The installer detects whether the machine is a server or desktop, uses your existing package manager when available, and on a machine with no Node.js sets up Node.js LTS with `mise`, adding mise's shims to `~/.profile` so new login shells find `threatcrush`. If it finds an older Node.js it stops without installing anything and tells you how to upgrade.

- **Linux server** → installs the CLI
- **Desktop (Linux, macOS, Windows)** → installs the CLI and points you to the desktop app, a separate download from [GitHub Releases](https://github.com/profullstack/threatcrush/releases/latest). The desktop app talks to a ThreatCrush daemon on the same machine; log monitoring and firewall bans need Linux.

After install, the supported lifecycle commands are:

```bash
threatcrush update   # upgrades the installed bundle
threatcrush remove   # removes the installed bundle
```

Manual package-manager installs still work (Node.js 22.6+):

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
threatcrush modules list                # List built-in and installed modules
threatcrush modules install ssh-guard   # Install a module
threatcrush modules install docker-monitor
threatcrush store search "firewall"     # Search marketplace
threatcrush store publish https://github.com/you/my-module  # Publish your own
```

### Built in

| Component | What it covers |
|-----------|----------------|
| `log-watcher` | nginx access log + syslog — 96 OWASP CRS rules (PL1: SQLi, XSS, path traversal, RFI, RCE, PHP/Java injection, SSRF, scanners) + 4 ThreatCrush rules (OS files in the path; PHPUnit, ThinkPHP and XWiki RCE probes) scored on every request |
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
threatcrush init                    # Auto-detect & generate config
threatcrush init --offline          # Same, without signing in (scripts, CI, containers)
```

Config lives at `/etc/threatcrush/threatcrushd.conf` with module configs in `/etc/threatcrush/threatcrushd.conf.d/`.

### Local shell history protection

Command-history collection is opt-in because shell histories may contain credentials or private work details:

```toml
[command_history]
enabled = true
```

The system daemon checks Bash, Zsh, Fish, and Ksh history files every minute, keeps compressed local snapshots under `/var/lib/threatcrush/command-history/`, and retains up to 96 archived snapshots plus the current backup per file for up to 90 days. The directory is root-only. Snapshot contents stay on the host and are never sent to the dashboard. If a history file is replaced by a symlink, hard link, or removed after a backup exists, the daemon restores the last snapshot and emits a medium-severity event. Re-run `threatcrush install-service` after enabling collection so systemd grants write access only to supported interactive users' home directories.

Snapshots contain only commands the shell has flushed to its history file. Bash commonly writes its in-memory history when the shell exits, so these backups are an audit trail, not a real-time activity clock or proof of hours worked. Use OS command auditing when you need complete per-command records.

### Findings in the cloud

Signed in (`threatcrush login`), every `scan`, `pentest` and `ai-scan` result is
saved to your current org (`threatcrush orgs use <slug>`), where findings are
tracked across runs: new, still open, and fixed automatically once a later run of
the same scope no longer sees them. Triage them in the CLI, on the web
(threatcrush.com/org/&lt;slug&gt;/findings, installable as a PWA), in the desktop
app (Findings, sign in with your browser) or over MCP (`findings_list`,
`findings_get`, `findings_triage` at threatcrush.com/api/mcp):

```bash
threatcrush findings                       # open + acknowledged
threatcrush findings --status all --severity critical,high --source ai-scan
threatcrush findings show 3f2a9c1d
threatcrush findings ack|fix|fp|ignore|reopen 3f2a9c1d 7b1e… --note "why"
```

In CI, set `THREATCRUSH_API_KEY` to a `tc_agent_` key with write and runs
upload into that key's org with no login (workflow example in
docs/SCANNING.md). `--no-upload` (or `THREATCRUSH_UPLOAD=0`) keeps a run local. A repo is named by
its origin remote (credentials stripped); URL targets lose their query string.

### Usage counts

Each `threatcrush ai-scan` / `ai-scan-run` sends one anonymous count to the API
(`THREATCRUSH_API_URL`, default threatcrush.com): command, CLI version, OS, Node
version, CI or not, a random install ID (`~/.threatcrush/usage-ping.json`), and
probe/finding counts and run time. Never the target, prompts, responses or
finding text. Turn it off with `THREATCRUSH_TELEMETRY=0` or `DO_NOT_TRACK=1`.
Requests to our API also carry the user agent `threatcrush/<version>`.

## Cloud dashboard

The daemon reports to your ThreatCrush dashboard once the machine is logged in and linked to a server there:

```bash
threatcrush login                      # prints a link: approve it in a browser where you are signed in
threatcrush servers link               # reuses the dashboard server with this hostname, or registers one
threatcrush servers link --org acme --name web-1
threatcrush save                       # store this machine's daemon config on its server (secrets redacted)
threatcrush status                     # shows the link
threatcrush servers unlink             # stop reporting
```

`threatcrush login` needs no browser on the machine and never asks for a password: it prints a `threatcrush.com/cli/login` link and a short code, you approve it from any signed-in browser after checking the code matches, and the terminal finishes signing in on its own (PKCE-bound, so only the terminal that started it can redeem it; the link expires after 10 minutes). Each machine gets its own session. `threatcrush login --password` keeps the email-and-password prompt.

`threatcrush save` uploads the config the daemon reads (`/etc/threatcrush/threatcrushd.conf` as root). Values under keys that look like secrets (passwords, tokens, webhook URLs, API keys) are replaced with `[redacted]` before upload, and again by the server.

A running daemon picks up `link` and `unlink` within a minute; no restart. It then:

- uploads detections at or above `[cloud] min_severity` (rule detections, plus events from modules no rule reads, such as dns-monitor), batched (100 events or every 10 s), and every ban and unban the daemon makes;
- sends a heartbeat every 60 s with its version and hostname;
- runs the `threatcrush harden` checks and `threatcrush patches` a minute after it starts and every 24 h, and uploads the findings (both commands upload too; `--no-upload` skips it);
- every 15 s, picks up blocks and unblocks queued on the dashboard and applies them through auto-defence, so protected and allowlisted addresses and dry-run apply as they do locally;
- every 5 min, adds the organization's IP/CIDR allowlist to the never-block set (an entry wider than /8 for IPv4 or /16 for IPv6 is ignored, and the dashboard can never remove a built-in, shared-infrastructure or locally configured protected address).

What the dashboard can make a daemon do is limited to block, unblock, allowlist add/remove, restart, and "update now" (which installs the newest `@profullstack/threatcrush` from the npm registry; the dashboard never supplies a version, URL or command). Property scans and pentests queued on the dashboard run on a machine only when its operator opts in, and then only for the linked organization:

Uploads never hold up detection or a ban. While the dashboard is unreachable, events wait in a spool (`/var/lib/threatcrush/cloud-spool.jsonl`, or `~/.threatcrush/state/` for a user daemon) of at most 10,000 events / 20 MB, oldest dropped first, which survives a restart and is sent when the dashboard answers again. The daemon uses the login of the user it runs as (`/root/.threatcrush/config.json` for the system service) and refreshes the session itself; if the refresh token is refused, it logs that `threatcrush login` is needed and keeps spooling.

```toml
[cloud]
enabled = true            # false: the daemon neither reports to nor takes actions from the dashboard
min_severity = "medium"   # info | low | medium | high | critical
runs = false              # true: run property scans/pentests queued on the dashboard here
run_scan_paths = []       # the only directories a dashboard scan may read; empty refuses scans
```

Pentests from the dashboard only reach public addresses: a target that resolves to loopback, a private range or link-local (cloud metadata) is refused.

### Every machine, with what it costs

The Fleet panel lists linked daemons. To also list the machines that do not run one, and what each box costs a month, upload an [OpenDevice](https://logicsrc.com/docs/opendevice) inventory (org owners and admins):

```bash
threatcrush fleet import opendevice.json         # or an https:// URL; --org <slug> to pick the org
threatcrush fleet cost                           # per-box $/mo, provider, daemon status and the total
```

Devices are matched to linked servers by hostname, name or IP. A device with no daemon shows as "no agent"; a cost the inventory does not state shows as "unstated" and is never guessed. Totals are per currency, never converted. `GET /api/fleet/costs` returns the recurring costs in the shape CoinPay imports.

## Automatic updates

The daemon keeps itself on the latest release. About every 6 hours (plus up to an hour of jitter, so a fleet does not restart in step) it asks the npm registry for `latest`. When a newer version has been published for at least 2 hours, and is on the same major version, it installs it and restarts onto it. The update shows in the live feed as an info event (`auto-update`).

Under systemd the unit's sandbox keeps the daemon from writing its own install, so it hands `npm i -g` to a transient unit (`systemd-run`) run as whoever owns the install, then restarts the service. A user-mode daemon runs npm itself. Only the npm global layout the installer produces is updated in place. A daemon running from a pnpm store or a source checkout logs that `threatcrush update` is needed instead. A version that was tried and did not take is not retried for a day.

```toml
[update]
auto = true          # false (or THREATCRUSH_AUTO_UPDATE=0): upgrade by hand with `threatcrush update`
interval = "6h"      # how often to check (at least 15m)
min_age = "2h"       # how long a release must be public before it is taken
allow_major = false  # true: also move to a new major version
```

## Pricing

The CLI is MIT-licensed (see [License](#license)). For pricing, [contact us for a quote](https://threatcrush.com/hire).

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
