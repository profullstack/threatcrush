# code-scanner

Static analysis on codebases. `PRD.md` scopes this module to "vulnerabilities,
secrets, misconfigs, dependency CVEs" — four different detection models over the
same directories, so the module is a thin host and each one is a **subsystem**:

| Subsystem | Covers | Status |
| --- | --- | --- |
| `deps/` | Dependency advisories, malicious install scripts, lockfile drift | **implemented** ([PRD 0002](../../prd/0002-detect-vulnerable-and-malicious-dependencies-on-running-servers.md)) |
| `secrets/` | Hardcoded credentials, redacted by construction | **implemented** ([PRD 0003](../../prd/0003-detect-hardcoded-secrets-before-they-are-committed-or-served.md)) |
| `sast/` | Source-level vulnerability analysis | not yet built |
| `config/` | Misconfiguration checks | not yet built |

```bash
threatcrush modules install code-scanner
threatcrush scan --deps /srv/app
```

PRD 0002 originally proposed the dependency work as a standalone `dep-scanner`
module and left the boundary open. It is resolved in favour of folding in: two
modules would have walked the same trees, held two inventories of the same
packages, and given the operator two path lists to keep in sync — for a
user-visible surface (`threatcrush scan --deps`) that was always meant to be one
command. What survives the fold is the *internal* separation, because `deps/`
owns an external advisory database and a per-ecosystem parser surface that has
nothing in common with a secrets regex pass.

## Why the deps subsystem exists

Two failures motivated this module, and both are things the existing tools do
badly or cannot do at all.

**A scanner that can't read your project should not say "good".** A
general-purpose analyzer pointed at a real 13-package pnpm workspace reported:

```
Direct dependencies: 0
Found 0 circular dependencies
Coupling score: 0/100 (low - good)
```

Every number was wrong. It read the root `package.json`, never resolved
`pnpm-workspace.yaml`, found nothing, and called the nothing *good*. For a
productivity tool that wastes an afternoon; for a security tool it is a clean
bill of health issued without an examination. Run against the same workspace,
this subsystem reports **21 project roots and 101 packages**, and marks the root `partial`
with the reason — because a pnpm lockfile is not parsed yet, and saying so is
the entire point.

**An advisory database cannot catch a package that is malicious today.**
`event-stream` (2018), `ua-parser-js` (2021) and `node-ipc` (2022) were all
advisory-clean at the moment they were installed — the advisory gets written
*after* somebody notices. What they shared was the execution vector: a
lifecycle script running with the installing user's privileges and network
access. So this module reads what install scripts actually *do*, independently
of whether anyone has filed a CVE.

## What it detects

| Detector | Needs network | Catches |
| --- | --- | --- |
| **Advisories** (OSV.dev) | yes | Known CVEs/GHSAs in installed versions, with the fix version |
| **Install-script behaviour** | no | Remote code fetches, encoded payloads, credential reads, geolocation probes, persistence |
| **Lockfile drift** | no | Installed bytes that disagree with the resolved lockfile — a 2am hotfix, or tampering |
| **Parse failures** | no | Projects that could not be read, so they never count as clean |

OSV is used rather than a vendor feed because it aggregates GHSA, PyPA, RustSec
and the Go vulnerability database behind one schema and needs no API key —
which matters for a module meant to be on by default for operators with no
security budget.

## Design decisions worth knowing

**Zero runtime dependencies.** A dependency scanner that drags in a dependency
tree of its own is a poor advertisement for itself. This ships with only the
ThreatCrush SDK. That is affordable because OSV expresses affected versions as
ordered `introduced`/`fixed` events over concrete versions, so matching needs
version *comparison* — implemented here to semver 2.0.0 §11, prerelease rules
included — rather than a full npm range grammar.

**Rank, never silently suppress.** Dev-only findings are demoted one severity
level and still reported. There is no `ignore` setting, because a finding an
operator never sees is indistinguishable from one that was missed. This makes
the module look noisier than commercial scanners that suppress by default; that
is the intended trade.

**The installed tree wins over the lockfile.** The lockfile records what
*should* be there; `node_modules` is what will actually execute tonight. Where
they disagree, the disagreement is itself a finding.

**Heuristics are worded behaviourally, not accusatorially.** A script that
"pipes a network download into a shell" is a fact an operator can check.
Known native-build tooling (`node-gyp`, `prebuild-install`) is *discounted, not
excluded* — hiding behind a legitimate build step is precisely what an attacker
would do.

## What this does not do

Scope of this release is **Discover, Detect and Report**. Deliberately absent:

- **No remediation.** No auto-upgrade, no auto-`npm install`, no rollback.
  Upgrading a transitive dependency under a running production service is more
  likely to cause the outage than prevent one.
- **No true integrity verification yet** (PRD 0002 R13). npm records integrity
  over the published *tarball*, not the extracted tree, so a faithful check
  needs the tarball. Version drift is detected; byte-level tampering within a
  version is not.
- **npm ecosystem only.** Python, Go, Rust, PHP, Ruby and OS packages
  (dpkg/rpm) are specified in the PRD and not yet built.
- **`pnpm-lock.yaml` and `yarn.lock` are not parsed.** pnpm projects resolve
  through workspace manifests plus the installed tree and report `partial`;
  Yarn PnP reports `failed`. Both are honest about it rather than empty.
- **No reachability analysis.** Findings are ranked by dev-vs-runtime only.

## Configuration

See [`config/example.conf.toml`](./config/example.conf.toml). Defaults live in
`mod.toml` and are safe to run unattended: alert-only, no containment, capped
alert volume.

## Development

```bash
pnpm install
pnpm build
pnpm test
```

The test suite includes a permanent regression test for the reference failure
above: a fixture pnpm workspace whose members' dependencies **must** be found.
If that test ever passes with an empty package list, the module has regressed
into the tool it was written to replace.

## Licence

MIT — Profullstack, Inc.
