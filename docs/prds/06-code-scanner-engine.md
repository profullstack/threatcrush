# PRD — Code scanner engine

- **Status:** Draft · Not started
- **Surface(s):** CLI (`apps/cli/src/commands/scan.ts`), Web (`/api/scan`)
- **Priority:** P1
- **Owner:** TBD
- **Related:** `docs/PRD.md` §"Example detection categories" · README "Code Security Scanner" · [[16-module-marketplace]]

## Problem

`threatcrush scan ./src` is advertised to find "vulnerabilities, hardcoded
secrets, and misconfigurations" and dependency CVEs. The command exists
(`scan.ts`, ~279 lines) and there is a `/api/scan` route, but the depth and
coverage need a written spec to reach launch quality — especially the claimed
**dependency CVE** scanning and **deep scan** (the `scan.deep` usage-billed
action in `docs/PRE_LAUNCH.md`).

## Goals

1. Define the scan coverage tiers: secrets, static vuln patterns, misconfig, dependency CVEs.
2. Specify the free local scan vs the usage-billed `scan.deep` (AI-assisted) tier.
3. Stable, machine-readable output (JSON) + human report.
4. Findings optionally persist to the server for the dashboard.

## Non-goals

- Full SAST replacing dedicated tools (Semgrep/CodeQL depth) at launch.
- IDE integration.

## Current state

- `commands/scan.ts` (~279 lines) and `apps/web/src/app/api/scan/route.ts` exist — audit actual coverage vs claims before writing detail.
- `scan.deep` rate is configured in `docs/PRE_LAUNCH.md` (CoinPayPortal usage billing) implying an AI tier is intended.

## Requirements

1. **Secrets**: entropy + known-token regexes; allowlist for false positives.
2. **Static patterns**: language-aware risky-call detection (start with JS/TS, Python).
3. **Misconfig**: common insecure config files / permissions.
4. **Dependency CVEs**: parse lockfiles, check against an advisory source.
5. **Deep scan (`scan.deep`)**: AI-assisted triage, metered via CoinPayPortal; default model = latest Claude (Opus 4.8) per repo guidance; require explicit opt-in (cost).
6. **Output**: `--json`, severity per finding, exit codes for CI use.

## Acceptance criteria

- [ ] Documented coverage matrix; claims in README match implemented checks.
- [ ] Secrets + dependency CVE detection verified against a seeded fixture repo.
- [ ] `scan.deep` gated behind opt-in + usage billing; degrades to free scan without keys.

## Out of scope / later

- Multi-language SAST parity with dedicated tools.
- PR/CI bot integration.

## Open questions

- Advisory data source for dependency CVEs (OSV, GitHub Advisory DB)?
- Is `scan.deep` launch-blocking or a fast-follow?
