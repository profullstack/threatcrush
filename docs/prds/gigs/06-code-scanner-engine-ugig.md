# Mature the ThreatCrush code scanner engine

> ugig.net gig posting — implements [PRD-06](../06-code-scanner-engine.md)

- **Title:** Mature the ThreatCrush code scanner engine
- **Skills required:** `typescript`, `nodejs`, `static-analysis`, `security`, `secrets-detection`, `cve`, `llm-integration`
- **Budget type:** fixed
- **Budget (USD):** 2,000 – 3,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/code-scanner`
- **Spec:** `docs/prds/06-code-scanner-engine.md`

## What we need

`threatcrush scan ./src` exists but its coverage needs to reach launch quality
and match the README's claims (vulnerabilities, secrets, misconfig, dependency
CVEs) plus the usage-billed `scan.deep` AI tier.

## Scope

1. Secrets (entropy + known-token regexes, with allowlist), language-aware static
   risky-call detection (JS/TS, Python first), common misconfig checks.
2. Dependency CVEs: parse lockfiles, check against an advisory source (OSV /
   GitHub Advisory DB).
3. `scan.deep`: AI-assisted triage, metered via CoinPayPortal, explicit opt-in;
   default model = latest Claude (Opus 4.8) per repo guidance; degrade to the free
   scan when no keys/credits.
4. Output: `--json`, severity per finding, CI-friendly exit codes; optional
   persistence of findings for the dashboard.

## Acceptance criteria

- Documented coverage matrix; README claims match implemented checks.
- Secrets + dependency-CVE detection verified against a seeded fixture repo.
- `scan.deep` gated behind opt-in + billing; gracefully degrades without keys.
- PR with green CI.
