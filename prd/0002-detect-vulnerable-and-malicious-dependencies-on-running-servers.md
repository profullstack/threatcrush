---
openprd: "0.2"
id: "0002"
title: "Detect vulnerable and malicious dependencies on running servers"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation: modules/code-scanner (deps subsystem)
tags: code-scanner, deps, supply-chain, sbom, cve, osv, install-scripts, drift, supply-chain-scanning, modules
supersedes:
superseded-by:
---

## Problem

`PRD.md` already promises this twice — `threatcrush scan --deps` in the CLI, and
"dependency CVEs" in the `code-scanner` row — but neither is specified or built.
This PRD scopes it, because the naive version of this feature is worse than
having none.

**The failure mode that matters is a false negative rendered as a pass.** On
2026-07-28 a general-purpose dependency analyzer was run against a real 13-package
pnpm workspace — 173 files, 29,519 lines, every service and package depending on
shared internal packages. It reported:

```
Direct dependencies: 0
Internal modules: 5
Found 0 circular dependencies
Coupling score: 0/100 (low - good)
```

Every number is wrong, and the tool said **"good"**. It parsed the root
`package.json`, found only devDependencies there, never resolved the
`pnpm-workspace.yaml` globs, and reported the resulting silence as health. A
developer-productivity tool that does this wastes an afternoon. A *security*
tool that does this tells an operator their server is clean when nothing was
ever examined. **A scanner that cannot distinguish "I found no vulnerabilities"
from "I could not read this project" is an actively dangerous artifact**, and
most of them cannot: pnpm workspaces, npm overrides, Yarn PnP, vendored
directories, lockfile-less installs and monorepo hoisting all produce this
silence.

**The threat is no longer only *vulnerable* dependencies — it is *malicious*
ones.** The industry record is unambiguous:

- **`event-stream` (Nov 2018)** — maintainer transferred the package to a
  volunteer, who added a dependency that lifted credentials from a specific
  bitcoin wallet. A package with millions of weekly downloads, compromised by
  social engineering, not by a CVE.
- **`ua-parser-js` (Oct 2021)** — maintainer's npm account hijacked; three
  versions shipped a cryptominer and a password stealer, executed from a
  `preinstall` script.
- **`node-ipc` (Mar 2022)** — the maintainer himself shipped destructive
  protestware that overwrote files based on the host's geolocation.
- **`xz-utils` / CVE-2024-3094 (Mar 2024)** — a multi-year social-engineering
  campaign put a backdoor in a compression library feeding sshd. Caught by an
  engineer investigating a ~500ms latency anomaly, not by any scanner.

None of those were CVEs *at install time*. A scanner that only joins installed
versions against an advisory database sees all four as clean, because the
advisory does not exist until after the damage. Meanwhile **the execution vector
is nearly always the same: a lifecycle script (`preinstall`/`postinstall`) that
runs with the installing user's privileges and can reach the network.**

**ThreatCrush is positioned to see what CI-based scanners structurally cannot.**
Dependabot, Snyk and `npm audit` run in a pipeline, against a manifest, before
deploy. ThreatCrush is a daemon on the box where the code actually runs. That
gives it three signals nobody in CI has:

1. **What is installed and running now** — not what a manifest claimed at merge
   time. Servers drift; hotfixes get `npm install`ed by hand at 2am.
2. **Change under a running service** — `node_modules` mutating without a
   deploy is either an unrecorded manual fix or an attacker, and both are worth
   an alert.
3. **Correlation with `network-monitor`** — an install script opening an
   outbound connection is the single highest-signal supply-chain event
   available, and ThreatCrush is already watching that socket on the same host.

## Goals

- An operator learns that a **known-vulnerable** dependency is installed on a
  running server within one scan interval, with a fix version where one exists.
- A **malicious or tampered** package is detectable **without waiting for a
  CVE**, via install-script behaviour, registry-integrity mismatch and drift.
- **"Unknown" is never reported as "clean."** Every scan states what it could
  and could not parse, and an unparseable project is a warning, not a pass.
- Findings are **ranked by whether they are actually reachable on this host** —
  a devDependency that never ships to production does not outrank an exposed
  runtime package.
- Noise is low enough that the module stays enabled. An alert stream nobody
  reads is identical to no scanner at all.

## Non-Goals

- **Not a replacement for Dependabot/Renovate.** Those open pull requests
  against a repository; this inspects a running host. Complementary, not
  competing — and this PRD does not propose ThreatCrush open PRs.
- **Not a general SAST engine.** Source-level vulnerability analysis, secret
  detection and misconfiguration scanning are `code-scanner`'s other subsystems
  (`sast/`, `secrets/`, `config/`) and are out of scope for this PRD. This work
  owns the dependency graph only — a package inventory, not source.
- **Not a license-compliance tool.** SBOM output must be reusable for that, but
  license policy enforcement is out of scope.
- **Not automatic remediation in v1.** No auto-upgrading, no auto-`npm install`,
  no auto-rollback. Upgrading a transitive dependency under a running production
  service is more likely to cause the outage than prevent one.
- **Not a private-registry proxy or install-time gate.** Blocking bad packages
  at install is the correct long-term control; it requires sitting in the
  install path, which is a different product.
- **Not vulnerability research.** Consume OSV/GHSA; do not attempt to originate
  advisories.

## Users

- **Solo founders and small teams** who deploy directly to a VPS and have no
  CI-based dependency scanning at all. Primary persona: the same operator
  PRD 0001 targets — the scan has to be free, on by default, and quiet.
- **Platform/ops engineers** running an estate of heterogeneous servers who need
  one honest answer to "which hosts are exposed to this advisory, right now?"
  after a Log4Shell-class disclosure.
- **Incident responders** who need to know whether a package changed on a host,
  when, and what it did on install.

## Requirements

### Discover

- R1 [P0] **Ecosystem detection and inventory.** Locate project roots under
  configured paths and produce a normalized package inventory:
  `ecosystem, name, version, direct|transitive, dev|runtime, path, integrity`.
- R2 [P0] **Lockfile-first resolution** for npm/pnpm/yarn — `package-lock.json`,
  `pnpm-lock.yaml`, `yarn.lock` — because the lockfile is the only honest record
  of the transitive closure. **Workspace globs must be resolved**
  (`pnpm-workspace.yaml`, `workspaces` in `package.json`); the reference failure
  in Problem is precisely this step being skipped.
- R3 [P0] **Installed-state resolution.** Walk `node_modules` and reconcile
  against the lockfile. Where they disagree, the **installed tree wins for
  reporting** and the divergence is itself a finding — that gap is where manual
  hotfixes and tampering live.
- R4 [P1] Additional ecosystems: Python (`requirements.txt`, `poetry.lock`,
  `uv.lock`, site-packages), Go (`go.mod`/`go.sum`), Rust (`Cargo.lock`),
  PHP (`composer.lock`), Ruby (`Gemfile.lock`).
- R5 [P1] **OS packages** via dpkg/rpm, so a `xz-utils`-class system library is
  in scope rather than only application dependencies.
- R6 [P0] **Parse failures are first-class output.** Every root reports
  `parsed | partial | failed` with a reason. A `failed` root raises a warning
  and is never counted toward a clean result.

### Detect — known vulnerabilities

- R7 [P0] **Advisory matching against OSV.dev** (covers GHSA, PyPA, RustSec,
  Go vulndb) with a locally cached database, correct semver-range matching per
  ecosystem, and offline operation against the last sync.
- R8 [P0] **Severity, CVSS, fixed-version and advisory URL** on every finding.
  A finding without a remediation path is an interrupt, not information.
- R9 [P1] **Runtime-reachability ranking.** Downgrade findings in packages that
  are dev-only or absent from the production tree; upgrade findings in packages
  loaded by a process the daemon can see running. Approximate is fine and must
  be labelled as approximate — this is a *ranking* input, never a reason to
  suppress silently.
- R10 [P2] **Function-level reachability** (is the vulnerable symbol imported at
  all) as an additional ranking input. Explicitly research-grade; must never
  suppress a finding on its own.

### Detect — malicious and tampered packages

- R11 [P0] **Install-script inventory.** Enumerate every `preinstall`,
  `install` and `postinstall` script in the tree, with its package and command.
  This is the primary execution vector for npm supply-chain attacks and most
  operators have never seen the list for their own server.
- R12 [P0] **Install-script heuristics.** Flag scripts that fetch remote code,
  pipe to a shell, decode base64/hex blobs, write outside the package
  directory, read credential paths (`~/.npmrc`, `~/.aws`, `~/.ssh`, env dumps),
  or invoke a shell from a `node -e` one-liner.
- R13 [P0] **Integrity verification.** Compare installed package content against
  the lockfile's recorded integrity hash. A mismatch means the bytes on disk are
  not the bytes that were resolved — a **critical** finding regardless of
  advisory status.
- R14 [P1] **Drift detection.** Watch dependency trees of running services and
  alert when a package is added, removed or changes version **without a
  corresponding deploy**. This is the signal no CI scanner can produce.
- R15 [P1] **Install-script network correlation.** When `network-monitor` is
  active, correlate outbound connections observed during an install window with
  the packages whose scripts ran. Directly targets the `ua-parser-js` pattern.
- R16 [P1] **Supply-chain reputation heuristics** on the metadata, not the
  code: package age vs. install count, a first release after long dormancy,
  recent maintainer change, typosquat distance to a popular package name,
  publish-time anomalies. Each weak alone; useful in combination, and each must
  be individually disableable.
- R17 [P2] **Registry cross-check.** Verify the installed tarball hash against
  what the public registry currently serves, to catch a re-published version.

### Report

- R18 [P0] **`threatcrush scan --deps`** one-shot, with a non-zero exit on
  findings at or above a configurable severity, so it is usable as a CI gate.
- R19 [P0] **Scheduled daemon scans** with alerts through `alert-system`,
  deduplicated per `(package, version, advisory)` so a long-lived vulnerability
  alerts on discovery and on escalation — never once per interval.
- R20 [P1] **SBOM export** in CycloneDX and SPDX. The inventory is already
  built; emitting it standardizes the output and makes the module useful to
  compliance workflows without becoming one.
- R21 [P1] **Estate query.** Given an advisory or package name, answer which
  hosts are affected. This is the Log4Shell morning question.
- R22 [P2] Dashboard surface in the existing TUI/desktop apps.

## UX Notes

Ships as the `deps` subsystem of the core `code-scanner` module, following the
existing module contract (`mod.toml`, config in
`threatcrushd.conf.d/code-scanner.conf`, alerts routed through `alert-system`),
matching `spend-guard`. Dependency-specific settings are namespaced `deps_*` so
the sibling subsystems — `secrets`, `sast`, `config` — can be configured
alongside without collision, while `paths`, `min_severity` and the scan interval
stay shared.

```bash
threatcrush scan --deps                      # one-shot, current directory
threatcrush scan --deps /srv/app --json      # machine-readable
threatcrush scan --deps --fail-on high       # CI gate (non-zero exit)
threatcrush code-scanner deps inventory      # what is installed, per root
threatcrush code-scanner deps scripts        # every install script in the tree
threatcrush code-scanner deps drift          # changes since last scan
threatcrush code-scanner deps sbom --format cyclonedx > sbom.json
threatcrush code-scanner deps sync           # refresh the advisory database
threatcrush code-scanner deps why lodash     # who pulls this in, and is it runtime
```

Config sketch:

```toml
[code-scanner]
enabled = true
paths = ["/srv", "/var/www", "/opt/app"]
scan_interval = "6h"
min_severity = "medium"        # alerting floor, shared by every subsystem

# Never report a pass for a root that could not be parsed.
fail_on_unparseable = true

[code-scanner.deps]
enabled = true
advisories = "osv"
sync_interval = "12h"
offline_ok = true              # match against last sync rather than skipping
dev_dependencies = "rank_down" # rank_down | equal — deliberately no "ignore"
install_scripts = true
integrity_mismatch = "critical"
drift = "high"
reputation_heuristics = true

[code-scanner.report]
dedupe_window = "30d"
max_alerts_per_scan = 25       # summarize beyond this rather than flooding
```

An alert must lead with exposure and remediation, and must state its own
blind spots:

```
[HIGH] code-scanner · /srv/qrypt-chat · 3 runtime advisories, 1 integrity mismatch

  CRITICAL  integrity mismatch  ua-parser-js@0.7.29
            on-disk hash != lockfile integrity — installed bytes are not the
            resolved bytes.  postinstall runs: node -e (base64 blob)
            → quarantine and reinstall from a clean lockfile

  HIGH      CVE-2024-XXXXX     ws@7.4.6 → fixed in 7.5.10
            runtime, reachable (loaded by pid 2244 `node server.js`)

  Scanned 4 roots (3 parsed, 1 FAILED: /srv/legacy — yarn PnP unsupported)
  1 root was not examined. This result is not a clean bill of health.
```

Design constraints:

- **A scan that could not parse a project must say so louder than a scan that
  found nothing.** The default posture is "unknown", not "clean". This is the
  entire lesson of the Problem section.
- **Rank, do not silently suppress.** Dev-only and unreachable findings are
  demoted and still listed; a suppressed finding an operator never sees is
  indistinguishable from a missed one.
- **One alert per incident.** A vulnerability present for 90 days must not
  generate 360 alerts.
- **Every finding carries its next action** — fix version, or "no fix
  available; here is the exposure".

## Success Metrics

- **Reference-failure regression:** scanning a 13-package pnpm workspace
  correctly reports every workspace package and its transitive closure. The
  `0 dependencies / coupling 0 / "good"` result is a **failing test**, permanently.
- **Honesty:** for every deliberately-broken fixture (missing lockfile, Yarn
  PnP, vendored tree, unreadable permissions) the scan reports `failed`/`partial`
  and never a clean pass. Target: 100%. This is the one metric with no
  acceptable shortfall.
- **Malicious-package recall:** replaying the known-bad versions of
  `event-stream`, `ua-parser-js` and `node-ipc` as fixtures, each is flagged by
  at least one *non-advisory* detector (install-script heuristic, integrity, or
  reputation) — proving the module does not depend on a CVE existing.
- **Advisory accuracy** ≥99% agreement with `osv-scanner` on a corpus of real
  lockfiles, with disagreements triaged rather than tolerated.
- **Noise:** median ≤2 actionable alerts per host per week at default config on
  a maintained project; zero alerts on a freshly-scaffolded project with no
  known-vulnerable dependencies.
- **Performance:** a 2,000-package tree scans in <10s warm, <60s cold, with the
  advisory DB cached under 200 MB.

## Risks & Open Questions

- ~~**Module boundary with `code-scanner` is unresolved.**~~ **Resolved
  2026-07-28: folded into `code-scanner` as the `deps/` subsystem.** Two
  modules would have walked the same trees, held two inventories of the same
  packages, and given the operator two path lists to keep in sync — for a
  user-visible surface (`scan --deps`) that was always meant to be one command.
  `PRD.md` already assigned "dependency CVEs" to `code-scanner`, so folding in
  makes the module tree match the product doc instead of contradicting it, and
  no amendment is needed. The arguments for splitting (a package-graph data
  model, an external advisory database, a per-ecosystem parser surface that will
  keep growing) were real but are all *internal*, so they are preserved as a
  subsystem boundary under `src/deps/` rather than a module boundary. Siblings
  `secrets/`, `sast/` and `config/` are stubs for the rest of `code-scanner`'s
  remit.
- **Reachability analysis is where scanners lose credibility in both
  directions.** Too eager and it suppresses a real finding; too timid and the
  operator drowns. v1 uses it only to *rank* (R9), never to suppress — but that
  guarantees a higher raw alert count than commercial tools that do suppress,
  and the module will look noisier in comparison. **Open:** is an opt-in
  `suppress_unreachable` acceptable, given a suppressed finding is invisible?
- **Reputation heuristics will produce false accusations.** "Recent maintainer
  change" plus "publish after dormancy" describes both a supply-chain attack and
  a healthy project changing hands. Calling a legitimate maintainer's package
  malicious is a reputational harm the *project* absorbs. Mitigation: these
  never fire alone at high severity, wording stays behavioural
  ("this package changed hands recently") rather than accusatory, and each
  heuristic is individually disableable.
- **Advisory database size and freshness on small hosts.** A full OSV mirror is
  large; a stale one silently under-reports. **Open:** ship a filtered mirror
  covering only detected ecosystems, and treat sync age as a health signal that
  alerts when it exceeds a threshold?
- **Install-script scanning has a privacy and blast-radius edge.** Enumerating
  and heuristically judging scripts means reading vendor code on the host;
  findings may embed snippets. Alerts must redact by default and never ship
  package source off-box without explicit opt-in.
- **Drift detection (R14) needs a deploy signal it does not own.** Without
  knowing when a legitimate deploy happened, every deploy looks like drift.
  **Open:** infer from process restart and mtime clustering, or require an
  explicit `threatcrush code-scanner deps ack-deploy` hook in the user's deploy
  script? The latter is accurate and adds integration burden.
- **This module reads dependency trees, which frequently contain credentials in
  adjacent files** (`.npmrc`, `.env`). It must never log or transmit them, and
  the `code-scanner` secret detector — not this one — owns finding them.
- **Open:** free core module or paid marketplace? PRD 0001 leaves the same
  question open for `spend-guard`. Consistency argues for answering both at
  once; the fact that `PRD.md` already lists dependency CVEs under a *core*
  module argues this one is core.
