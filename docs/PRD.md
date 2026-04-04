# PRD — Open Source Linux Server Security Platform

## Product name

Product name: ThreatCrush

Domain: threatcrush.com

## Summary

Build ThreatCrush, an open source Linux server security platform focused only on Linux servers and security-sensitive infrastructure workloads. The product should help operators secure internet-facing Linux boxes with a lightweight agent, a central dashboard, and opinionated protections for SSH, auth logs, firewall remediation, suspicious behavior detection, and hardening recommendations.

This product is not trying to be a full SIEM, EDR, or enterprise SOC platform. It is a simpler, easier-to-operate alternative for self-hosters, indie hackers, small businesses, MSPs, and small DevOps teams that want practical server protection without a huge learning curve.

The main wedge is:

* Linux only
* open source core
* one-line install
* opinionated defaults
* low-noise security events
* fleet visibility for small to medium server fleets
* built-in remediation and hardening guidance

## Goals

1. Protect Linux servers from common internet-facing attacks quickly.
2. Replace or complement tools like fail2ban with richer detection logic.
3. Provide a clean, centralized view across multiple servers.
4. Offer useful remediation with minimal config.
5. Keep the open source version highly usable and credible.
6. Build on a stack that supports a hosted cloud control plane later.

## Non-goals

1. Full antivirus or kernel-level EDR in v1.
2. Windows or macOS endpoint support.
3. Deep Kubernetes-first security in v1.
4. Full packet inspection or IDS appliance replacement.
5. Compliance automation suite in v1.
6. Enterprise SOC workflows, SOAR, or multi-year retention in v1.

## Target users

### Primary

* Self-hosters running VPS or dedicated Linux servers
* Indie hackers running public apps on Ubuntu / Debian / Rocky / Alma / CentOS-like systems
* Small SaaS teams with 1 to 100 Linux servers
* MSPs managing Linux infrastructure for clients
* Security-conscious sysadmins who want something lighter than enterprise tools

### Secondary

* Agencies hosting client apps
* OSS maintainers running public infrastructure
* Homelab users with exposed services

## Core problem

Linux servers exposed to the internet are constantly hit by SSH brute force, credential stuffing, bot traffic, exploit probes, port scans, and misconfiguration risks. Existing options are often:

* too narrow, like fail2ban only
* too complex, like full SIEM stacks
* too enterprise-heavy
* too noisy
* too fragmented across separate tools

Users want a practical tool that says:

* what is happening
* how serious it is
* what the tool already blocked
* what still needs operator action
* how to harden the box further

## Product vision

The easiest open source way to secure Linux servers.

A user installs one agent, connects it to a dashboard if desired, and immediately gets:

* SSH and auth attack detection
* firewall-based auto-remediation
* suspicious activity alerts
* box hardening recommendations
* a simple fleet health view

## Key differentiators

1. Linux-only focus

   * No distraction from desktop endpoints or broad cross-platform support.

2. Opinionated defaults

   * Works well out of the box with minimal setup.

3. Open source core

   * Self-hostable, auditable, and community-extensible.

4. Lower noise

   * Fewer junk detections, more actionable signals.

5. Secure by default

   * Least privilege agent design, signed updates, audited event ingestion.

6. Small fleet first

   * Optimized UX for 1 to 100 servers, not just huge enterprises.

## Default stack

### Frontend

* Next.js
* React
* TypeScript
* Tailwind CSS
* Progressive Web App support for installable mobile/desktop-like dashboard access

### Backend

* Node.js
* TypeScript
* Next.js API routes or separate Node service where needed

### Database and auth

* Supabase Postgres
* Supabase Auth for dashboard accounts
* Supabase Realtime optionally for live event streaming

### Agent and client apps

* Node.js + TypeScript for the first Linux agent prototype
* Packaged as a Linux service with a lightweight CLI installer
* Systemd service support required
* CLI app for server enrollment, status, findings, remediation controls, and local-only operation
* Desktop app for fleet monitoring and server control
* PWA dashboard for browser-based and installable access to fleet monitoring and controls

### Open source repo structure

* apps/web — marketing site and PWA dashboard
* apps/api — optional dedicated backend services if needed
* apps/agent — Linux security agent
* apps/desktop — desktop dashboard app, likely Electron-based using the shared web UI where practical
* apps/cli — CLI app for admin workflows and local control
* packages/shared — shared types, schemas, utilities
* packages/ui — UI components
* packages/detections — detection rules and parsers
* packages/sdk — optional future SDK for plugins / integrations

## Product editions

### Open source edition

Includes:

* local Linux agent
* SSH/auth detections
* firewall remediation
* local CLI reports and controls
* hardening checks
* optional self-hosted central dashboard
* PWA dashboard access
* desktop dashboard app
* community rules

### Hosted cloud edition later

Possible paid additions:

* hosted fleet dashboard
* longer retention
* team access
* alert routing integrations
* premium threat intel feeds
* multi-tenant MSP controls
* audit exports and advanced reporting

## User stories

### Single server operator

* As a user, I want to install the tool with one command so I can secure a new VPS quickly.
* As a user, I want brute-force attackers blocked automatically so I do not have to configure iptables manually.
* As a user, I want a daily summary of important activity so I do not have to read raw logs.
* As a user, I want hardening suggestions so I can improve SSH and system configuration safely.

### Small team / fleet user

* As an operator, I want to see all servers in one dashboard.
* As an operator, I want to know which server is currently under attack.
* As an operator, I want to compare security posture across servers.
* As an operator, I want alerts only when something matters.

### MSP user

* As an MSP, I want to group servers by client.
* As an MSP, I want separate views and access control per client.
* As an MSP, I want reusable baseline policies.

## Functional requirements

### 1. Linux agent

The agent must:

* run on major Linux distributions
* install as a systemd service
* collect relevant log and system events
* parse auth and service logs
* evaluate local detections
* execute local remediation actions when configured
* queue and transmit events to a central API securely
* continue functioning locally if the dashboard is offline

Supported sources in v1:

* journald
* /var/log/auth.log
* /var/log/secure
* sshd logs
* sudo logs where available
* optional Nginx / Apache auth-related logs later

### 2. Detection engine

The system must support rule-based detections first.

Initial detection coverage:

* SSH brute force attempts
* repeated failed auth attempts across usernames
* successful login after multiple failures
* root login attempts
* logins from new countries or unusual geos if IP enrichment is enabled
* sudo abuse patterns
* basic port scan indicators from firewall or log signals
* exploit probe patterns against common services where logs are available
* repeated 404/403 or admin path probing on web servers later

Detection system requirements:

* detection rules are versioned
* rules are community-editable in the OSS edition
* severity levels: low, medium, high, critical
* suppression / cooldown support to reduce noise
* machine-readable rule schema

### 3. Auto-remediation

The system must support local remediation actions.

Initial remediation actions:

* block IP via nftables or iptables
* temporary ban with expiry
* permanent blocklist option
* optional SSH lockdown recommendations
* optional disable root SSH recommendation

Requirements:

* dry-run mode
* action audit trail
* allowlist support
* ban duration controls
* rollback / unblock controls

### 4. Hardening checks

The product should include a local hardening scanner.

Initial checks:

* password authentication enabled for SSH
* root login enabled
* weak SSH config patterns
* missing automatic security updates
* firewall inactive
* common exposed ports
* fail2ban already installed
* suspicious world-writable directories in sensitive locations
* risky service exposure findings

Output:

* pass / warning / fail states
* plain-English explanation
* recommended fix
* optional autofix later for safe items only

### 5. Dashboard

The web dashboard, PWA dashboard, and desktop dashboard must provide the same core monitoring experience wherever possible.

* login and account management
* fleet overview
* per-server event feed
* server health summary
* hardening findings view
* remediation history
* rules view
* allowlist / blocklist management
* alert settings

Views:

1. Overview

   * total servers
   * recent threats
   * blocked IPs
   * servers needing attention

2. Server detail

   * current status
   * recent detections
   * remediation actions
   * hardening score
   * software / distro metadata

3. Detections

   * filter by severity, rule, hostname, timeframe

4. Findings

   * hardening issues and fix guidance

5. Policies later

   * shared remediation and detection settings

### 6. Client applications

#### PWA dashboard

The PWA must:

* be installable from supported browsers
* authenticate to a hosted or self-hosted ThreatCrush server instance
* show fleet and per-server stats
* show detections, findings, and remediation history
* support basic control actions such as acknowledge, unblock, allowlist, and alert settings where permissions allow
* work well on desktop and mobile form factors

#### Desktop app

The desktop app must:

* connect to a hosted or self-hosted ThreatCrush server instance
* provide the same core dashboard views as the web app
* support authenticated admin actions
* optionally support richer local notifications than the PWA
* prepare for future offline-friendly cached views

Suggested implementation:

* Electron shell around shared React UI for fastest delivery
* shared API client and UI packages across web and desktop

#### CLI app

The CLI must:

* install and enroll agents
* query local agent status
* print findings and detection summaries
* trigger safe remediation commands
* connect to remote ThreatCrush server instances for scripted administration

### 7. Alerting

V1 alerting should include:

* email alerts
* webhook alerts
* optional Slack / Discord later

Alert settings must support:

* thresholding
* severity filtering
* per-server subscriptions
* rate limiting

### 8. Self-hosting

The platform should support self-hosting.

Self-hosted requirements:

* docker-compose setup
* environment-variable-based config
* documented migration process
* documented agent enrollment flow

### 9. Security requirements

Because this is a security product, trust matters.

Requirements:

* agent-to-server communication must be authenticated
* API keys or signed enrollment tokens
* TLS required in production
* least-privilege design wherever possible
* sensitive secrets encrypted at rest where relevant
* audit log for important actions
* signed release artifacts preferred
* no silent remote code execution mechanism
* rules updates must be transparent and auditable

### 10. Privacy requirements

Users may not want to send raw logs to the cloud.

Requirements:

* local-first event processing where possible
* allow sending only normalized detections instead of raw logs
* configurable redaction
* self-hosted mode supports keeping all data in user control

### 11. OSS rule ecosystem

Need a community model for detections.

Requirements:

* rule pack format in repo
* metadata for distro/service compatibility
* test fixtures for log parsing
* rule validation CI
* easy contribution docs

## Non-functional requirements

### Performance

* agent CPU usage should remain low on idle servers
* agent memory footprint should stay modest
* detection latency should feel near real time

### Reliability

* agent should keep working when offline from central dashboard
* event queue retries required
* service should recover cleanly from restart

### Usability

* install in minutes
* useful defaults without requiring policy authoring
* docs written for non-security specialists

### Portability

Target Linux distros for v1:

* Ubuntu LTS
* Debian stable
* Rocky Linux / AlmaLinux
* optionally Fedora later

## Proposed data model

### tables

#### users

* id
* email
* created_at

#### organizations

* id
* name
* domain
* owner_user_id
* created_at

#### organization_members

* id
* organization_id
* user_id
* role

#### servers

* id
* organization_id
* hostname
* distro
* kernel_version
* public_ip
* agent_version
* last_seen_at
* enrollment_token_hash
* status
* created_at

#### detections

* id
* organization_id
* server_id
* rule_id
* severity
* title
* description
* source_ip
* username
* raw_metadata_json
* detected_at

#### remediation_actions

* id
* organization_id
* server_id
* detection_id
* action_type
* target_value
* status
* executed_at
* expires_at
* metadata_json

#### hardening_findings

* id
* organization_id
* server_id
* finding_key
* severity
* status
* title
* recommendation
* observed_at
* resolved_at

#### alert_destinations

* id
* organization_id
* type
* config_json
* created_at

#### alert_rules

* id
* organization_id
* name
* min_severity
* server_scope_json
* destination_id

#### client_sessions

* id
* organization_id
* user_id
* client_type
* last_seen_at
* metadata_json

#### allowlists

* id
* organization_id
* type
* value
* note
* created_at

#### rule_registry

* id
* rule_id
* version
* title
* category
* source_path
* enabled_by_default
* created_at

## API concepts

### agent enrollment

* POST /api/agent/enroll
* validate token
* issue agent credential

### event ingest

* POST /api/events
* accept normalized detection and health payloads

### heartbeat

* POST /api/heartbeat
* update server status and metadata

### remediation sync later

* GET /api/policies
* GET /api/rules

### dashboard APIs

* GET /api/servers
* GET /api/detections
* GET /api/findings
* GET /api/remediations
* GET /api/overview/stats
* POST /api/remediations/execute
* POST /api/allowlists
* POST /api/blocklists

## Initial UX flow

### First-time dashboard user

1. User signs up.
2. User creates organization.
3. User gets install command with enrollment token.
4. User runs installer on Linux server.
5. Agent registers and appears in dashboard.
6. Initial hardening scan runs.
7. User sees findings and recommended actions.
8. Incoming detections begin appearing in real time.

### First-time CLI-only user

1. User installs agent locally.
2. Agent runs in local-only mode.
3. User views local report command output.
4. User optionally enables auto-remediation.
5. User optionally connects to a self-hosted or hosted dashboard later.

## MVP scope

MVP should include:

* Linux agent
* CLI app
* PWA dashboard
* desktop dashboard app
* SSH/auth log parsing
* rule-based detection engine
* nftables or iptables IP blocking
* hardening scanner
* dashboard auth and server list
* overview stats
* detections feed
* remediation history
* email alerts
* self-hostable stack
* docs and install scripts

MVP should not include:

* Kubernetes support
* WAF
* deep malware scanning
* SIEM integrations beyond webhooks
* advanced threat intel marketplace
* anomaly ML models
* Windows/macOS support

## Stretch goals after MVP

### Phase 2

* Nginx / Apache probe detections
* geo-IP enrichment
* Slack / Discord alerts
* fleet policy templates
* team roles
* MSP multi-tenant mode

### Phase 3

* richer service integrations
* dashboard diffing of hardening posture
* package vulnerability overview
* safe autofix actions
* optional managed threat feeds

### Phase 4

* plugin SDK
* detection marketplace
* advanced reporting
* more sophisticated behavior correlation

## Success metrics

### Product

* time to first protected server under 10 minutes
* first meaningful detection within first week for exposed boxes
* high percentage of users enabling remediation
* low false-positive complaint rate

### Adoption

* GitHub stars
* self-host installs
* active agents per week
* community rule contributions
* dashboard-connected servers

### Retention

* 30-day active server retention
* weekly returning dashboard users
* low uninstall rate after first week

## Risks

1. Node agent performance or privilege model may become limiting.

   * Mitigation: keep detection logic lean and leave room to rewrite the agent later in Rust or Go if needed.

2. False positives damage trust.

   * Mitigation: conservative defaults, test corpus, allowlists, dry-run mode.

3. Firewall differences across distros create support burden.

   * Mitigation: support a small set first, abstract remediation backend.

4. Users compare against much broader platforms.

   * Mitigation: stay focused on Linux server protection and simplicity.

5. Security products are held to a higher trust bar.

   * Mitigation: transparent architecture, auditable code, open rule packs, signed releases.

## Competitive positioning

### vs fail2ban

* broader detections
* central dashboard
* hardening checks
* better UX

### vs CrowdSec

* narrower scope
* more opinionated Linux-only setup
* simpler fleet workflows
* potentially easier self-hosting story

### vs SIEM / EDR products

* much lighter
* easier to understand
* lower operational overhead

## Technical implementation notes

### Agent approach

The agent can start as a local daemon that:

* tails journald or log files
* normalizes events
* runs rules against event windows
* calls local firewall adapters
* emits periodic heartbeats and findings

### Firewall abstraction

Implement adapters:

* nftables adapter first
* iptables adapter second if needed
* keep interface generic so other remediation backends can be added later

### Rule format

Use JSON or YAML with a typed schema. Each rule should define:

* id
* title
* description
* source types
* matching conditions
* thresholds
* time window
* severity
* remediation suggestions
* tags

### Example detection categories

* auth
* ssh
* privilege escalation
* reconnaissance
* web probes
* persistence indicators later

## Open source strategy

The project should be permissively licensed if broad adoption is the top goal, or source-available / dual-licensed if hosted monetization protection matters more. This decision should be made early.

Recommendations to define early:

* license choice
* contribution guidelines
* code of conduct
* public roadmap
* community rule submission process

## Launch strategy

### Initial audience

* self-hosters on Reddit, Hacker News, and security communities
* indie hackers running VPS-based SaaS
* open source sysadmin communities
* small MSPs

### Launch assets

* GitHub repo
* docs site
* one-line installer
* benchmark / comparison page vs fail2ban
* demo dashboard screenshots
* tutorial: securing a fresh Ubuntu VPS in 5 minutes

## Open questions

1. Should the agent remain Node-based long term or only for MVP?
2. Should raw logs ever be uploaded by default? likely no.
3. Which Linux distros are mandatory at launch?
4. Should local-only mode have a small embedded UI or CLI only?
5. Should the self-hosted dashboard be included in the OSS repo from day one?
6. How much of the rules ecosystem should be curated centrally?
7. Should cloud be multi-tenant from day one or added later?

## Recommended MVP build order

1. Agent installer and systemd service
2. Log collection and normalization
3. SSH/auth detections
4. Local firewall remediation
5. Hardening scanner
6. Dashboard auth and organization model
7. Server enrollment and heartbeat
8. Detections view
9. Findings view
10. Email / webhook alerting
11. Dockerized self-host package
12. Documentation and launch site

## Brand and positioning

Product name: ThreatCrush

Domain: threatcrush.com

Tagline direction: Crush threats on Linux servers before they become incidents.

## One-sentence positioning

ThreatCrush is an open source, Linux-only server defense platform that combines practical detections, automatic blocking, and hardening guidance with a simple fleet dashboard across web, PWA, desktop, and CLI clients.
