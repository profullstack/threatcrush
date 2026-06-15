# PRD — Detection rule engine & rule packs

- **Status:** Draft · Not started
- **Surface(s):** CLI (`apps/cli/src/daemon`), SDK
- **Priority:** P0
- **Owner:** TBD
- **Related:** `docs/PRD.md` §2 "Detection engine", §11 "OSS rule ecosystem" · [[00-detection-data-model]] · [[09-module-sdk-and-publish]]

## Problem

Detections today are hardcoded inside the `ssh-guard` module
(`apps/cli/src/modules/ssh-guard`) and the journal/log watchers. There is no
versioned, declarative rule format, no severity taxonomy, no
suppression/cooldown, and no community contribution path — all of which the PRD
calls for and which the README's "1,247 attack signatures" headline implies
exist. A security product's credibility hinges on transparent, auditable rules.

## Goals

1. Define a typed, declarative rule schema (JSON/YAML) per PRD §"Rule format".
2. Build an engine that evaluates rules over event windows from watchers.
3. Ship a curated default rule pack (auth/ssh/recon to start).
4. Severity levels (low/medium/high/critical), thresholds, time windows, suppression/cooldown.
5. Make rules community-editable with validation in CI (PRD §11).

## Non-goals

- ML/anomaly detection (PRD post-MVP).
- Behavioral correlation across hosts (Phase 4).

## Current state

- `apps/cli/src/modules/ssh-guard/` — bespoke logic, not rule-driven.
- `apps/cli/src/daemon/watchers/{journal-watcher,log-watcher}.ts` — produce events.
- No `packages/detections` rule pack dir (PRD proposed it).

## Requirements

1. **Rule schema** (typed in `apps/sdk`): id, title, description, source_types, match conditions, threshold, window, severity, remediation suggestions, tags, distro/service compatibility metadata.
2. **Engine**: consume normalized events from watchers, maintain sliding windows, emit detections that conform to [[00-detection-data-model]].
3. **Rule packs**: a repo dir (e.g. `apps/cli/rules/` or `packages/detections/`) with versioned packs; loaded at daemon start; hot-reload optional.
4. **Suppression/cooldown**: per-rule + per-source dedupe to cut noise.
5. **Versioning**: register loaded rules into `rule_registry`.
6. **Validation CI**: schema validation + log-fixture tests for each rule.

## Initial detection coverage (port ssh-guard into rules)

SSH brute force; repeated failed auth across usernames; success-after-failures;
root login attempts; sudo abuse; basic port-scan indicators; exploit-probe
patterns where logs allow.

## UX / surface

- `threatcrush rules list` / `rules show <id>` / `rules test <fixture>`.
- Rule files loadable from `/etc/threatcrush/rules.d/` for operator overrides.

## Acceptance criteria

- [ ] Rule schema published from `apps/sdk` and documented.
- [ ] `ssh-guard` detections regenerated from rules (no behavioral regression vs current).
- [ ] CI validates every shipped rule + runs fixture tests.
- [ ] Suppression demonstrably collapses repeat events.

## Out of scope / later

- Central curated rule feed / auto-updates (ties to [[16-module-marketplace]]).

## Open questions

- JSON vs YAML for authored rules? (YAML friendlier for contributors; JSON simpler to validate.)
- Do the "1,247 signatures" claims need to be backed before launch, or is the README copy revised?
</content>
