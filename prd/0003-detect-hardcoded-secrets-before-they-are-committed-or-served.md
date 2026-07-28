---
openprd: "0.2"
id: "0003"
title: "Detect hardcoded secrets before they are committed or served"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation: modules/code-scanner (secrets subsystem)
tags: code-scanner, secrets, credentials, entropy, redaction, modules
supersedes:
superseded-by:
---

## Problem

`PRD.md` lists "secrets" in `code-scanner`'s remit and `threatcrush scan
--secrets` is already in the CLI surface. Neither is specified or built.

**A leaked credential is the shortest path from a code mistake to a full
compromise.** It needs no exploit, no privilege escalation and no CVE: whoever
holds the string has the access. It is also the finding class with the worst
half-life, because a secret committed once is permanent — rotating it is the
only remediation, and deleting the file does not help once it is in a git
object, a Docker layer, a CI log or a backup.

**ThreatCrush's angle is again the running host, not the repository.** This
repo already runs `gitleaks` in CI and carries a `.gitleaksignore`, so the
commit path is covered. What is not covered is everything that reaches a server
*without* passing through a commit:

- a `.env` written by hand during a 2am fix and never removed,
- a `config.json.bak`, `dump.sql` or `id_rsa` left in a web root,
- credentials baked into a built artifact in `dist/` that no scanner reads
  because it is gitignored,
- a `.git` directory served by a misconfigured nginx, exposing every secret
  ever committed even after removal.

A repository scanner cannot see any of those, because none of them are in the
repository. The daemon is standing on the disk where they live.

**The second problem is that secret scanners are famous for being unusable.**
High-entropy heuristics match minified JavaScript, base64 test fixtures, UUIDs,
lockfile integrity hashes and git SHAs. A scanner that reports two hundred
findings on first run gets switched off, and a switched-off scanner detects
nothing — the same failure mode PRD 0002 confronted from the other direction.
Precision is not a nice-to-have here; it is the feature.

**Third, the scanner itself becomes a disclosure risk.** A finding that quotes
the secret moves it into an alert channel, a log file and a Slack history. The
report must prove a secret is there without reproducing it.

## Goals

- A credential sitting in a file on a running server is found within one scan
  interval, identified by **kind** (AWS key, GitHub token, private key), with
  the location precise enough to fix it.
- **Findings never reproduce the secret.** Alerts, logs and events carry a
  redacted fingerprint sufficient to identify and verify, never the value.
- Precision high enough that the module stays enabled: a first run on a normal
  project yields a reviewable handful, not a wall.
- **Verified findings rank above heuristic ones.** A credential with a
  structurally valid, checksummed format is a different class of fact from
  "this string looks random", and must not be presented as the same.
- Exposure severity accounts for **reachability**: a secret inside a directory
  served by a running web server outranks the same secret in a source tree.

## Non-Goals

- **Not a git-history scanner.** `gitleaks`/`trufflehog` in CI own the commit
  path and this repo already runs them. This scans the filesystem as it exists,
  including files that were never committed. History is out of scope, with the
  deliberate exception of an exposed `.git` directory (see R9).
- **Not a secret-manager or rotation tool.** Report and prove; rotating a
  credential is the operator's action, and doing it automatically would be an
  outage generator.
- **Not credential validation against live providers by default.** Testing
  whether a found AWS key still works means sending someone's credential to a
  third party from their server. Opt-in only, never a default (see Risks).
- **Not dependency or source-vulnerability scanning** — those are `code-scanner`'s
  `deps/` (PRD 0002) and `sast/` (PRD 0004) subsystems.

## Users

- **Solo founders and small teams** deploying to a VPS by hand, where `.env`
  files and one-off backups accumulate in web roots. Primary persona.
- **Platform/ops engineers** who need to answer "is anything on this host
  holding a live credential?" without cloning every repo on it.
- **Incident responders** establishing blast radius after a host compromise:
  what could the attacker have read?

## Requirements

### Find

- R1 [P0] **Filesystem walk** over configured paths, sharing `code-scanner`'s
  root discovery and skip rules. Binary files are skipped by content sniff, not
  by extension.
- R2 [P0] **Size and type bounds.** Files above a configurable size are sampled
  rather than skipped silently, and skips are reported — an unscanned file must
  never be indistinguishable from a clean one (the PRD 0002 honesty rule).
- R3 [P0] **High-risk filenames** are scanned even when they would otherwise be
  skipped: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `.npmrc`, `.pgpass`,
  `credentials`, `*.kdbx`, `.aws/*`, `.docker/config.json`.
- R4 [P1] **Gitignored files are scanned, and flagged as such.** They are the
  *most* likely to hold real credentials and the *least* likely to have been
  seen by a repo scanner. This inverts the usual default deliberately.

### Detect

- R5 [P0] **Structured pattern rules** for credentials with a recognizable
  shape: AWS access keys, GitHub/GitLab tokens, Slack tokens, Stripe keys,
  Google API keys, OpenAI/Anthropic keys, private key PEM blocks, JWTs, basic
  auth in URLs, connection strings with inline passwords.
- R6 [P0] **Checksum verification where the format defines one.** Stripe and
  GitHub tokens carry a checksum; a candidate that fails it is a lookalike, not
  a leak. This is the single highest-value precision lever available.
- R7 [P1] **Entropy scoring** as a secondary signal for unstructured secrets,
  gated by context (assignment to a key named `secret`/`token`/`password`) so
  that raw entropy alone never raises a finding on its own.
- R8 [P0] **Suppression of known non-secrets**: lockfile integrity hashes, git
  SHAs, UUIDs, base64-encoded images, minified bundles, example/placeholder
  values (`AKIAIOSFODNN7EXAMPLE`, `sk_test_`, `xxx`, `changeme`), and test
  fixtures. Each suppression is a named rule, so a wrong one can be found and
  fixed rather than being invisible tuning.
- R9 [P1] **Exposure context.** Raise severity when the file is inside a
  directory served by a running web server, or is an exposed `.git`. Lower it
  for test fixtures and example files. Ranking only — never suppression.

### Report

- R10 [P0] **Redaction is mandatory and structural.** A finding carries kind,
  file, line, a masked preview (`AKIA****************7EXAM`) and a SHA-256
  fingerprint of the value. The raw secret is never written to an event, alert,
  log or state. There is no configuration option to disable this.
- R11 [P0] **Fingerprint-based dedupe** so the same credential in the same place
  alerts once, and a rotated-then-reintroduced secret alerts again.
- R12 [P1] **Allowlist** by fingerprint, path glob and rule id, stored in config
  so a reviewed false positive stays quiet without disabling the rule globally.
- R13 [P1] **`threatcrush scan --secrets`** one-shot with `--fail-on` for CI
  use, sharing output shape with `scan --deps`.
- R14 [P2] **Opt-in liveness check** for providers with a zero-cost identity
  endpoint (e.g. AWS `sts:GetCallerIdentity`), strictly disabled by default,
  strictly logged when it runs.

## UX Notes

Ships as the `secrets` subsystem of `code-scanner`, configured under `secrets_*`
keys alongside `deps_*`, sharing `paths`, `min_severity` and the scan interval.

```bash
threatcrush scan --secrets /srv/app
threatcrush scan --secrets --fail-on high        # CI gate
threatcrush code-scanner secrets rules           # what is being matched, and why
threatcrush code-scanner secrets allow <fingerprint>   # record a reviewed false positive
```

```toml
[code-scanner.secrets]
enabled = true
entropy = true                 # unstructured secrets, context-gated
scan_gitignored = true         # they are the likeliest and least-scanned
max_file_bytes = 5_000_000
allow = ["sha256:9f86d0…", "tests/fixtures/**"]
```

An alert proves the finding without leaking it:

```
[CRITICAL] code-scanner · secrets · AWS access key in a served directory

  /var/www/app/.env.bak:12   aws_access_key_id
  AKIA****************7EXAM   sha256:9f86d081…
  checksum: valid · inside nginx root for app.example.com · not in git

  Rotate the key, then delete the file. Deleting alone is not remediation.
```

Design constraints:

- **Never print the secret.** The masked preview keeps the first four and last
  five characters, which is enough for a human to locate it in the file and not
  enough to use.
- **Say why it matched.** "Matched rule `aws-access-key-id`, checksum valid"
  is auditable; "high entropy" is not.
- **Remediation is rotation, and the alert must say so.** Operators routinely
  delete the file and consider it handled.

## Success Metrics

- **Precision:** on a corpus of real project trees, ≥90% of `high`/`critical`
  findings are genuine credentials. Structured-and-checksummed findings target
  ~100%.
- **Recall on known formats:** 100% detection of a fixture set covering every
  rule in R5, including keys split across line continuations.
- **Noise:** zero findings on a freshly scaffolded project (Next.js, Vite,
  Express, FastAPI) with no credentials committed. This is the acceptance test
  that keeps the module switched on.
- **No leakage:** an automated test asserts that for a fixture secret, the
  raw value appears in **no** emitted event, alert body or log line. This test
  is not optional and cannot be satisfied by configuration.
- **Performance:** 100k files scanned in <60s on one core.

## Risks & Open Questions

- **The scanner is itself a disclosure vector.** Findings travel to Slack,
  email and log files. Redaction (R10) is structural rather than configurable
  for exactly this reason, and the no-leakage test is a hard gate. **Open:**
  should the fingerprint be salted per host, so alert history cannot be used to
  correlate the same credential across customers?
- **Liveness checking is genuinely dangerous.** Verifying an AWS key proves the
  finding and removes all doubt; it also transmits a customer credential to a
  third party from their server, and a wrong implementation could lock an
  account through failed-attempt throttling. Default off, opt-in per provider,
  and never for arbitrary/unknown key types.
- **Scanning gitignored files (R4) will surface real secrets in developer
  scratch space** and may feel invasive on a shared host. It is the right
  default for a *server* and possibly the wrong one for a workstation. **Open:**
  should the default flip based on whether the host looks like a server?
- **Entropy tuning is where every scanner in this category fails.** Gating it
  behind a contextual key name (R7) sacrifices recall on genuinely random
  secrets stored in bare arrays. That trade is deliberate — a module that is
  switched off has zero recall — but it should be revisited with real corpus
  data rather than assumed correct.
- **Allowlists decay into blanket suppression.** A fingerprint allowlist is
  precise; a path glob is not, and `tests/**` will eventually hide a real
  credential. **Open:** should glob allowlists expire, or require a re-review
  after N days?
- **Open:** shared with PRD 0002 — free core or paid marketplace? `PRD.md`
  lists secrets under a core module, which argues core.
