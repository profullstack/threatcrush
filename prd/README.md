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
