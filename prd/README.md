# ThreatCrush PRDs

Numbered [OpenPRD](https://github.com/profullstack/logicsrc/blob/master/docs/openprd.md)
product requirements documents for this repo. One file per PRD at
`prd/<id>-<slug>.md`, four-digit ids, no gaps. Copy `0000-template.md` to start
a new one.

Status lives in each file's front-matter and is the source of truth:
`Draft → Review → Accepted → Final`, or `Rejected` / `Withdrawn` / `Superseded`.

The root `PRD.md` predates this directory and describes the product as a whole;
these numbered PRDs cover individual changes to it.

| ID | Title | Status | Tags |
| --- | --- | --- | --- |
| [0001](./0001-detect-and-contain-balance-drain-attacks-on-third-party-services.md) | Detect and contain balance-drain attacks on third-party services | Draft | spend-guard, billing, fraud, sms-pumping, irsf, auto-recharge, containment, modules |
| [0002](./0002-detect-vulnerable-and-malicious-dependencies-on-running-servers.md) | Detect vulnerable and malicious dependencies on running servers | Draft | code-scanner, deps, supply-chain, sbom, cve, osv, install-scripts, drift, modules |
| [0003](./0003-detect-hardcoded-secrets-before-they-are-committed-or-served.md) | Detect hardcoded secrets before they are committed or served | Draft | code-scanner, secrets, credentials, entropy, redaction, modules |
| [0004](./0004-find-dangerous-code-patterns-without-pretending-to-be-a-compiler.md) | Find dangerous code patterns without pretending to be a compiler | Draft | code-scanner, sast, static-analysis, injection, taint, modules |
| [0005](./0005-catch-the-misconfigurations-that-actually-get-servers-breached.md) | Catch the misconfigurations that actually get servers breached | Draft | code-scanner, config, misconfiguration, hardening, exposure, modules |
| [0006](./0006-route-alerts-so-they-keep-being-read.md) | Route alerts so they keep being read | Draft | alert-system, routing, deduplication, escalation, notifications, modules |
| [0007](./0007-tell-ssh-compromise-apart-from-ssh-background-noise.md) | Tell SSH compromise apart from SSH background noise | Draft | ssh-guard, brute-force, authentication, tunneling, posture, modules |
| [0008](./0008-notice-what-changed-on-the-network-not-everything-on-it.md) | Notice what changed on the network, not everything on it | Draft | network-monitor, listeners, egress, port-scan, baseline, modules |
| [0009](./0009-read-the-logs-for-evidence-including-the-logs-that-stopped.md) | Read the logs for evidence, including the logs that stopped | Draft | log-watcher, logs, web-attacks, tampering, gaps, modules |
| [0010](./0010-block-attackers-without-locking-out-the-operator.md) | Block attackers without locking out the operator | Draft | firewall-rules, blocking, nftables, iptables, containment, modules |
| [0011](./0011-catch-the-exfiltration-channel-that-survives-egress-filtering.md) | Catch the exfiltration channel that survives egress filtering | Draft | dns-monitor, exfiltration, tunneling, dga, c2, modules |
| [0012](./0012-a-decoy-nobody-legitimate-touches.md) | A decoy nobody legitimate touches | Draft | honeypot, deception, decoy, high-precision, modules |
