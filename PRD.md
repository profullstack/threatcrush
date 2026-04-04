# ThreatCrush — Product Requirements Document

## Overview

ThreatCrush is an all-in-one security agent daemon that monitors, detects, scans, and pentests servers in real-time. It runs as a systemd service (`threatcrushd`) with a modular architecture where each capability is a pluggable module.

## Architecture

```
threatcrush (CLI)
  └── threatcrushd (daemon, systemd service)
       ├── Core Engine (module loader, config, IPC)
       ├── Module: network-monitor
       ├── Module: log-watcher
       ├── Module: ssh-guard
       ├── Module: code-scanner
       ├── Module: pentest-engine
       ├── Module: dns-monitor
       ├── Module: ... (community/paid modules)
       └── Alert System (slack, email, webhook, syslog)
```

## Directory Structure

```
/etc/threatcrush/                     # System config
  threatcrushd.conf                   # Main daemon config (TOML)
  threatcrushd.conf.d/                # Module configs (drop-in)
    network-monitor.conf
    log-watcher.conf
    ssh-guard.conf
    ...
  modules/                            # Installed modules
    network-monitor/
      mod.toml                        # Module manifest
      index.js                        # Entry point
    log-watcher/
      mod.toml
      index.js
    ...
  certs/                              # TLS certs for agent API
  license.key                         # License key (lifetime access)

/var/log/threatcrush/                 # Logs
  threatcrushd.log
  alerts.log
  audit.log

/var/lib/threatcrush/                 # Runtime data
  state.db                            # SQLite — events, stats, module state
  cache/                              # Temp files, signature cache
```

## CLI Commands

```bash
# Daemon management
threatcrush start                     # Start daemon (or systemctl start threatcrushd)
threatcrush stop                      # Stop daemon
threatcrush status                    # Show daemon status, active modules, threat count
threatcrush logs                      # Tail daemon logs
threatcrush logs --module ssh-guard   # Tail specific module logs

# Monitoring (foreground mode)
threatcrush monitor                   # Run in foreground (all modules)
threatcrush monitor --module network-monitor,ssh-guard

# Scanning (one-shot)
threatcrush scan ./src                # Scan codebase for vulnerabilities
threatcrush scan --secrets            # Scan for hardcoded secrets
threatcrush scan --deps               # Scan dependencies for CVEs

# Pentesting (one-shot)
threatcrush pentest https://example.com
threatcrush pentest --deep https://example.com/api
threatcrush pentest --report json     # Output report format

# Module management
threatcrush modules list              # List installed modules
threatcrush modules available         # List modules from marketplace
threatcrush modules install ssh-guard # Install from marketplace (free/paid)
threatcrush modules install ./my-module  # Install from local dir
threatcrush modules update            # Update all modules
threatcrush modules remove dns-monitor
threatcrush modules create my-module  # Scaffold a new module

# Marketplace
threatcrush store                     # Browse module store
threatcrush store search "firewall"   # Search modules
threatcrush store info ssh-guard      # Show module details, reviews, price
threatcrush store publish ./my-module # Publish a module

# Configuration
threatcrush init                      # Auto-detect services, generate config
threatcrush config                    # Edit main config
threatcrush config --module ssh-guard # Edit module config

# License
threatcrush activate <license-key>    # Activate lifetime license
threatcrush license                   # Show license status
```

## Modules

### Core Modules (included with lifetime access)

| Module | Description | What it monitors |
|--------|-------------|-----------------|
| `network-monitor` | Watches all TCP/UDP traffic on all ports | Connections, port scans, SYN floods, anomalous traffic patterns |
| `log-watcher` | Tails and analyzes server logs | nginx, Apache, syslog, journald, custom log paths |
| `ssh-guard` | Monitors SSH connections | Failed logins, brute force, key-based auth anomalies, tunneling |
| `code-scanner` | Static analysis on codebases | Vulnerabilities, secrets, misconfigs, dependency CVEs |
| `pentest-engine` | Active penetration testing | SQLi, XSS, path traversal, SSRF, auth bypass, API fuzzing |
| `dns-monitor` | Watches DNS queries and responses | DNS tunneling, DGA detection, suspicious resolutions |
| `firewall-rules` | Dynamic firewall management | Auto-blocks IPs after threshold, manages iptables/nftables |
| `alert-system` | Notification routing | Slack, Discord, email, webhook, PagerDuty, syslog |

### Community/Paid Modules (marketplace)

Anyone can build and publish modules. Examples:
- `wordpress-scanner` — WP-specific vulnerability checks
- `docker-monitor` — Container escape detection, image scanning
- `k8s-watcher` — Kubernetes cluster security
- `cloud-audit` — AWS/GCP/Azure IAM and config auditing
- `compliance-reporter` — SOC2, HIPAA, PCI-DSS report generation
- `threat-intel-feeds` — Integration with external threat intelligence
- `honeypot` — Deploy decoy services to detect attackers
- `rate-limiter` — Application-layer rate limiting
- `geo-blocker` — Block traffic by country/ASN
- `db-monitor` — Monitor PostgreSQL, MySQL, Redis for suspicious queries

### Module Manifest (`mod.toml`)

```toml
[module]
name = "ssh-guard"
version = "1.0.0"
description = "Monitor and protect SSH connections"
author = "ThreatCrush"
license = "MIT"
homepage = "https://threatcrush.com/modules/ssh-guard"

[module.pricing]
type = "free"  # free | paid | freemium
# price_usd = 29  # For paid modules

[module.requirements]
threatcrush = ">=1.0.0"
os = ["linux"]
capabilities = ["net_raw", "sys_ptrace"]  # Required Linux capabilities

[module.config]
# Default config values (can be overridden in conf.d/)
[module.config.defaults]
max_failed_attempts = 5
ban_duration_minutes = 30
whitelist = ["127.0.0.1"]
monitor_key_auth = true
```

### Module Config (`/etc/threatcrush/threatcrushd.conf.d/ssh-guard.conf`)

```toml
[ssh-guard]
enabled = true
max_failed_attempts = 3          # Override default
ban_duration_minutes = 60        # Override default
whitelist = ["127.0.0.1", "10.0.0.0/8"]
alert_channels = ["slack", "email"]
log_path = "/var/log/auth.log"   # Auto-detected, but overridable
```

### Module API

Modules are Node.js/TypeScript packages that implement the `ThreatCrushModule` interface:

```typescript
import { ThreatCrushModule, ModuleContext, Event, Alert } from '@threatcrush/sdk';

export default class SSHGuard implements ThreatCrushModule {
  name = 'ssh-guard';
  version = '1.0.0';

  async init(ctx: ModuleContext): Promise<void> {
    // Called when daemon starts or module is loaded
    // ctx.config — module config from conf.d/
    // ctx.state — persistent state (SQLite)
    // ctx.logger — structured logger
    // ctx.alert — send alerts
  }

  async start(): Promise<void> {
    // Start monitoring
    // Use ctx.subscribe('log:auth') to watch auth logs
    // Use ctx.subscribe('network:tcp:22') to watch SSH port
  }

  async onEvent(event: Event): Promise<void> {
    // Process events from subscribed sources
    if (event.type === 'log:auth' && event.data.includes('Failed password')) {
      // Track failed attempts, trigger alert/ban if threshold met
    }
  }

  async stop(): Promise<void> {
    // Cleanup when daemon stops
  }
}
```

### Module Installation via mise

For open-source/free modules, ThreatCrush uses [mise](https://mise.jdx.dev/) as the package manager:

```bash
# mise integration for module installation
threatcrush modules install ssh-guard
# Internally runs: mise install threatcrush-module-ssh-guard@latest
# Symlinks to /etc/threatcrush/modules/ssh-guard/

# From git
threatcrush modules install github:username/tc-module-honeypot

# From local
threatcrush modules install ./my-custom-module
```

For paid modules, the CLI authenticates with the ThreatCrush API, verifies the license, and downloads the module.

## Main Daemon Config (`/etc/threatcrush/threatcrushd.conf`)

```toml
[daemon]
pid_file = "/var/run/threatcrush/threatcrushd.pid"
log_level = "info"                  # debug, info, warn, error
log_file = "/var/log/threatcrush/threatcrushd.log"
state_db = "/var/lib/threatcrush/state.db"

[license]
key_file = "/etc/threatcrush/license.key"
# Or inline: key = "tc_live_..."

[api]
enabled = true
bind = "127.0.0.1:9393"            # Local API for CLI ↔ daemon IPC
tls = false                         # Enable for remote access

[alerts]
[alerts.slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/..."
min_severity = "medium"             # low, medium, high, critical

[alerts.email]
enabled = false
smtp_host = "smtp.gmail.com"
smtp_port = 587
from = "threatcrush@yourserver.com"
to = ["admin@yourserver.com"]

[alerts.webhook]
enabled = true
url = "https://your-api.com/webhooks/threatcrush"
secret = "your-hmac-secret"

[modules]
auto_update = true
update_interval = "24h"
module_dir = "/etc/threatcrush/modules"
config_dir = "/etc/threatcrush/threatcrushd.conf.d"
```

## Module Store / Marketplace

The ThreatCrush module store is hosted at `threatcrush.com/modules` (or could be on ugig.net as a collection).

### Store Features
- Browse/search modules by category
- View module details: description, author, version, downloads, reviews
- Install directly via CLI: `threatcrush modules install <name>`
- Publish modules via CLI: `threatcrush store publish ./my-module`
- Pricing: free, paid (one-time), or freemium
- Module verification: auto-scanned for security issues on submission
- Reviews and ratings

### Store API
```
GET    /api/modules                 # List modules (search, category, sort)
GET    /api/modules/:name           # Module details
POST   /api/modules                 # Publish module (auth required)
PATCH  /api/modules/:name           # Update module
POST   /api/modules/:name/install   # Register install (for download tracking)
POST   /api/modules/:name/review    # Leave a review
GET    /api/modules/:name/download  # Download module package
```

## Tech Stack

### CLI / Daemon
- **Runtime:** Node.js (TypeScript)
- **Package:** npm (`threatcrush` global install)
- **Daemon:** Node.js process managed by systemd
- **Config:** TOML (parsed with `@iarna/toml`)
- **State:** SQLite (via `better-sqlite3`)
- **Network capture:** Raw sockets via `cap` or `pcap` npm package, or `tcpdump` subprocess
- **Log watching:** `tail -f` via `fs.watch` + readline
- **Module loading:** Dynamic `import()` with sandboxing

### Landing Page / Store
- **Framework:** Next.js (already built)
- **DB:** Supabase
- **Payments:** CoinPayPortal + Stripe

## Pricing

| Tier | Price | Includes |
|------|-------|----------|
| Lifetime Access | $499 (or $399 with referral) | All core modules, CLI, daemon, API, lifetime updates |
| Module Store | Free to browse | Community modules free or paid per-module |
| AI-Enhanced | Usage-based | Pay per AI inference — threat classification, anomaly detection, smart alerts |
| Enterprise | Contact us | Custom modules, priority support, SLA |

## Roadmap

### Phase 1 — MVP (now)
- [x] Landing page with waitlist
- [x] Referral program
- [ ] CLI scaffold with `init`, `monitor`, `status` commands
- [ ] Core module: `log-watcher` (nginx/syslog)
- [ ] Core module: `ssh-guard`
- [ ] Alert system (webhook)
- [ ] systemd unit file

### Phase 2 — Beta
- [ ] Core module: `network-monitor` (pcap-based)
- [ ] Core module: `code-scanner`
- [ ] Core module: `pentest-engine`
- [ ] Module store on threatcrush.com
- [ ] `threatcrush modules install/publish` commands
- [ ] License activation

### Phase 3 — Launch
- [ ] Core module: `dns-monitor`
- [ ] Core module: `firewall-rules`
- [ ] Dashboard web UI (optional, self-hosted)
- [ ] Cloud sync (optional, send events to threatcrush.com)
- [ ] Enterprise features
