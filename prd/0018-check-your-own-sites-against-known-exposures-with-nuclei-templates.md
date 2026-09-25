---
openprd: "0.2"
id: "0018"
title: "Check your own sites against known exposures with nuclei templates"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-09-25
updated: 2026-09-25
repo: profullstack/threatcrush
discussion:
implementation:
tags: [pentest-engine, nuclei, templates, exposures, misconfiguration, dast, scanning, modules]
supersedes:
superseded-by:
---

## Problem

Until #217 the README sold a "Pentest Engine". What ships in `threatcrush pentest`
(`apps/cli/src/commands/pentest.ts`) is about a dozen fixed checks: a handful
of missing-header rules, cookie flags, a CORS wildcard, server-version
disclosure, directory listing, error-page disclosure, a reflected-XSS string
and a regex over the response body for sensitive-looking paths. Every one of
them inspects the response to a single request against the URL the operator
typed. None of them asks the question operators actually lose sleep over:
**is anything on my site exposed that a scanner on the internet will find
before I do?** A `.git/config` served from the web root, a `.env` next to it,
an unauthenticated admin panel, a debug endpoint left on, a dangling CNAME
waiting to be taken over.

Those are not novel vulnerabilities. They are **known shapes**, and the
security community already maintains a catalogue of them:
[ProjectDiscovery's nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT), several thousand YAML templates each describing a request and what a
positive response looks like. Attackers run this catalogue against the whole
internet continuously. An operator who does not run it against their own
sites is the last to learn what it says about them.

PRD 0016 defines the authorization gate and safety profiles for anything that
acts on a target. This PRD defines the first real test content to put behind
that gate.

## Goals

- `threatcrush pentest` finds the **known exposures and misconfigurations**
  that public scanners find, on the operator's own sites, before someone else
  does.
- The catalogue is **the community's, not ours**: templates are consumed from
  nuclei-templates at a pinned version, so coverage grows with upstream rather
  than with our headcount.
- The template count in marketing is **derived from the shipped table**, never
  typed by hand — the "1,247 signatures" problem does not recur here.
- The default run is **non-intrusive by construction**: detection-only
  templates, bounded requests, and no path to an address the operator has not
  verified (PRD 0016).

## Non-Goals

- **Not a nuclei reimplementation.** No DSL engine, no workflows, no fuzzing,
  no out-of-band (interactsh) interactions, no `code`, `javascript`,
  `headless`, `network`, `dns` or `ssl` protocol templates.
- **Not a dependency on the nuclei binary.** The daemon, the scheduled-run
  worker and the web deployment cannot assume it is installed. Operators who
  already run nuclei keep doing so; this is for everyone else.
- **Not exploitation.** A template that proves a vulnerability by exploiting
  it — sending a payload that writes, executes or extracts — is excluded, even
  when upstream marks it safe.
- **Not testing third parties.** Inherited unchanged from PRD 0016.

## Users

- **Solo founders and small teams** who have never scanned their own sites and
  will not learn nuclei to do it.
- **Operators already on ThreatCrush** who want one command, one report format
  (text / JSON / SARIF) and scheduled runs through existing properties.
- **Platform engineers** wanting a pre-deploy exposure check against staging in
  CI, failing the build on a high-severity finding.

## Requirements

### Template ingestion

- R1 [P0] **Pinned upstream version.** A generator script reads a specific
  nuclei-templates release tag and emits a compact, checked-in rule table
  (template id, name, severity, tags, references, requests, matchers). The
  version and the upstream licence/attribution ship alongside it and in the
  published npm package.
- R2 [P0] **Faithful or skipped.** A template is included only if every part
  of it can be evaluated exactly as nuclei would. Anything else is skipped
  with a recorded reason. No approximate rewrites: a template that half-works
  produces findings nobody can trust (PRD 0016's third hazard).
- R3 [P0] **Supported subset:** `http` (and legacy `requests`) blocks using
  `GET` or `HEAD`; `path` entries using only `{{BaseURL}}`, `{{RootURL}}` and
  `{{Hostname}}`; static headers; matchers of type `word`, `regex`, `status`
  and `size` with `part` (`body`, `header`, `all`, `status`), `condition`
  (`and`/`or`), `negative`, `case-insensitive`, and block-level
  `matchers-condition`; per-template redirect policy.
- R4 [P0] **Excluded by construction:** any template with `payloads`,
  `attack`, fuzzing, `raw` requests needing unsupported DSL, `dsl` matchers,
  extractors required for matching, OOB interaction, or a method other than
  `GET`/`HEAD`; any template tagged `dos`, `fuzz`, `fuzzing`, `intrusive`,
  `bruteforce`, `default-login` or `rce`.
- R5 [P0] **Generator reports its own coverage:** included count, and skipped
  count broken down by reason. That report is committed with the table, so a
  reviewer can see what an upstream bump changed.
- R6 [P1] The generated table has a **size budget** (target: under 2 MB
  uncompressed in the npm tarball). If the default selection exceeds it,
  categories are dropped from the default set, not truncated arbitrarily.

### Selection

- R7 [P0] **Default set** covers detection-only categories: `exposures`
  (config files, backups, VCS metadata, logs), `misconfiguration`,
  `exposed-panels`, `technologies`, and `takeovers` (detection only). CVE
  templates are included only when they are pure `GET`/`HEAD` detection with
  no exploit payload.
- R8 [P1] **Operator filtering** by tag, severity and template id, and a
  listing mode that prints what would run and how many requests it would send,
  without sending any.

### Runner

- R9 [P0] **Passes through PRD 0016's authorization gate** (R1–R4 there): no
  target is contacted unless it is on the allowlist and verified. Until 0016's
  gate is implemented, the template runner does not ship enabled.
- R10 [P0] **Never reaches private, loopback, link-local or metadata
  addresses** from the server side (web app, scheduled runs), reusing
  `apps/web/src/lib/ssrf-guard.ts`, including re-validation after redirects.
- R11 [P0] **Bounded load:** concurrency limit (default 10), requests-per-second
  limit, per-request timeout, and a global request budget per run. The help
  text states roughly how many requests a default run sends.
- R12 [P0] **Abort on harm:** stop the run if the target's `5xx` rate crosses
  PRD 0016's R8 threshold.
- R13 [P0] **Identifiable traffic:** a `User-Agent` naming ThreatCrush and the
  template id, so the operator can find the run in their own access logs — and
  so `log-watcher` on the same host can recognise its own scan and not ban
  itself (PRD 0010).
- R14 [P0] The existing built-in checks keep running; template findings are
  added, not substituted.

### Findings

- R15 [P0] Findings map onto the existing pentest finding format and severity
  scale, so text, JSON, SARIF output and stored property-run results keep
  working unchanged.
- R16 [P0] **Every finding carries the reproducing request** (method, URL,
  headers) and the matched evidence (the matcher that fired, the matched
  excerpt), per PRD 0016 R13.
- R17 [P1] Every finding links to the upstream template and its references,
  so the operator can read why it matters without trusting us.

### Honesty in claims

- R18 [P0] README, CLI README, site and deck describe pentest coverage using a
  number computed from the generated table (e.g. "N nuclei templates, pinned to
  vX.Y.Z"), updated by the same change that bumps the upstream version.

## UX Notes

```toml
[pentest-engine]
profile = "safe"                    # templates run only in safe and above
templates = "default"               # default | none | <comma-separated tags>
max_requests_per_run = 5000
requests_per_second = 5
concurrency = 10
```

```bash
threatcrush pentest verify https://app.example.com         # PRD 0016, mandatory first
threatcrush pentest https://app.example.com                # built-ins + default templates
threatcrush pentest https://app.example.com --templates exposures,misconfiguration --severity high
threatcrush pentest --list-templates --templates exposures  # what would run, no requests sent
threatcrush pentest https://app.example.com --format sarif --fail-on high
```

Output groups template findings by category, shows the template id next to
each finding, and ends with the run's request count against its budget. A
skipped-because-unsupported template never appears in output; it appears only
in the generator's coverage report.

## Success Metrics

- **Coverage:** the included-template count, and the share of the upstream
  catalogue's detection-only HTTP templates it represents, reported per
  upstream version.
- **Correctness:** on a fixture server deliberately exposing `/.git/config`,
  `/.env`, a directory listing and a known panel, every corresponding template
  fires; on a clean fixture, zero findings.
- **Parity:** for the included templates, findings match the nuclei binary's
  own results on the same fixture targets (checked in CI against a pinned
  nuclei version, where the binary is available).
- **Safety:** zero requests with a method other than `GET`/`HEAD`; zero
  requests to unverified or private addresses (asserted by test); default run
  stays within its stated request budget.
- **Load:** a default run against one site completes in under two minutes at
  the default rate limit.

## Risks & Open Questions

- **Even a `GET` can have side effects.** Some applications mutate state on
  `GET` (logout links, unsubscribe endpoints, cache purges). Detection-only
  templates target well-known paths, which lowers the odds but not to zero.
  State it in the documentation rather than gloss it, as PRD 0016 does.
- **Upstream churn.** nuclei-templates changes daily; templates are renamed,
  retagged and removed. The pin plus the committed coverage report make bumps
  reviewable; **open:** how often to bump, and whether a bump that drops
  coverage should fail CI.
- **Template quality varies.** Community templates occasionally produce false
  positives on catch-all 200 responses (SPAs returning `index.html` for every
  path). **Open:** add a per-target baseline request to a random
  non-existent path and suppress matches whose response equals the baseline.
- **Licence obligations.** nuclei-templates is MIT; the licence and copyright
  notice must travel with the generated table in every published artifact.
  Individual templates occasionally quote third-party material in references;
  we ship metadata and matchers, not the referenced content.
- **Self-ban.** A scan from the same host as `threatcrushd` looks like an attack
  to `log-watcher`. R13 addresses it; **open:** whether the daemon should
  allowlist its own scan runs by run id rather than by User-Agent, since a
  User-Agent is trivially forged by a real attacker.
- **Dependency on PRD 0016.** R9 makes this PRD's shipping date depend on
  0016's authorization gate, which is not implemented today. **Open:** whether
  to ship a CLI-only mode earlier that only accepts `localhost` and hosts
  resolving to the machine's own interfaces, which satisfies 0016's R2 by
  construction.
