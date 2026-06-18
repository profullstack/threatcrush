# Build the ThreatCrush detection rule engine & rule packs

> ugig.net gig posting — implements [PRD-01](../01-detection-rule-engine.md)

- **Title:** Build the ThreatCrush detection rule engine & rule packs
- **Skills required:** `typescript`, `nodejs`, `linux`, `security`, `log-parsing`, `json-schema`, `vitest`, `ci`
- **Budget type:** fixed
- **Budget (USD):** 2,000 – 3,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/detection-rule-engine`
- **Spec:** `docs/prds/01-detection-rule-engine.md`

## What we need

Detections today are hardcoded inside the `ssh-guard` module. We need a typed,
declarative rule format and an engine that evaluates rules over event windows
from the daemon's watchers — so detections are versioned, auditable, and
community-editable instead of buried in code.

## Scope

1. A typed rule schema (defined in `apps/sdk`): id, title, description,
   source_types, match conditions, threshold, window, severity, remediation
   suggestions, tags, distro/service compatibility.
2. An engine that consumes normalized events from `apps/cli/src/daemon/watchers`,
   maintains sliding windows, and emits detections conforming to PRD-00.
3. A curated default rule pack (auth/ssh/recon) loaded at daemon start; operator
   overrides from `/etc/threatcrush/rules.d/`.
4. Per-rule + per-source suppression/cooldown to cut noise; register loaded rules
   into `rule_registry`.
5. `threatcrush rules list|show <id>|test <fixture>`; CI that validates every
   shipped rule and runs log-fixture tests.

## Acceptance criteria

- `ssh-guard`'s current detections reproduced from rules with no regression.
- Suppression demonstrably collapses repeat events.
- CI validates all rules + fixtures; rule schema published from `apps/sdk`.
- PR with green CI and docs for authoring a rule.
