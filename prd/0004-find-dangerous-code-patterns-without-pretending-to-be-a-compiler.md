---
openprd: "0.2"
id: "0004"
title: "Find dangerous code patterns without pretending to be a compiler"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation: modules/code-scanner (sast subsystem)
tags: code-scanner, sast, static-analysis, injection, taint, modules
supersedes:
superseded-by:
---

## Problem

`PRD.md` lists "vulnerabilities" in `code-scanner`'s remit and
`threatcrush scan ./src` is already in the CLI. Neither is specified or built.

**The honest framing matters more here than in any other subsystem.** Real
static analysis — the kind that finds an injection by proving a path from an
untrusted source to a dangerous sink — needs a parser, a control-flow graph and
interprocedural taint tracking per language. CodeQL and Semgrep are each many
years of work, and this repo already runs both in CI.

So the question is not "can we build a SAST engine". It is **"what can a daemon
on a running server say about source code that is worth an operator's
attention, and can we say it without lying about our confidence?"**

Three things make a narrow version worth building:

**Pattern-level findings are genuinely useful and genuinely cheap.** A large
share of real-world web vulnerabilities are visible in a single expression:
`eval` on a request field, `child_process.exec` with a template literal, SQL
built by string concatenation, `res.send` of unescaped input, disabled TLS
verification, `dangerouslySetInnerHTML` fed by a variable. None of these need a
call graph to spot.

**CI-based analysis has a coverage hole that the daemon does not.** CodeQL runs
on the repository. The daemon reads what is on the server — vendored code,
generated files, a hotfix applied in place, a plugin dropped into a directory,
a build artifact that no longer matches its source. This is the same coverage
argument that motivated PRD 0002 and PRD 0003.

**Every scanner in this category loses trust the same way: by overclaiming.**
Reporting a regex match as though it were a proven data-flow finding trains
operators to disbelieve the tool. The `deps` subsystem's answer to this was to
distinguish "no vulnerabilities" from "could not parse"; the equivalent here is
to distinguish **"this is a dangerous construct"** from **"this is a proven
vulnerability"** — and to never claim the second from evidence that only
supports the first.

## Goals

- Dangerous constructs on a running server are surfaced within one scan
  interval, with file, line and an explanation an operator can verify by eye.
- **Confidence is stated, not implied.** Every finding declares whether it is a
  pattern match, a pattern match with a nearby untrusted source, or something
  stronger. No finding is presented as more certain than its evidence.
- Precision high enough to stay switched on: a first run on a normal codebase
  yields a reviewable list, not a wall of `eval` hits from vendored libraries.
- The subsystem is **honest about being narrow**. Documentation states plainly
  that this is not a replacement for CodeQL/Semgrep, so nobody turns those off.

## Non-Goals

- **Not a replacement for CodeQL or Semgrep**, both of which already run in this
  repo's CI. This complements them by running on servers rather than on
  repositories.
- **Not interprocedural taint analysis.** No call graph, no cross-file data
  flow, no framework-aware source/sink modelling. Claiming otherwise would be
  the overclaim this PRD exists to avoid.
- **Not a linter.** Style, complexity, dead code and formatting are out of
  scope; `code-scanner` is a security module and every finding must have a
  security consequence.
- **Not autofix.** Rewriting source on a running server is a change nobody
  asked a monitoring agent to make.
- **Not every language.** JavaScript/TypeScript first, because it is what
  ThreatCrush's own users deploy; others only when the rules are real rather
  than transliterated.

## Users

- **Solo founders and small teams** with no CI security analysis at all, for
  whom a pattern-level scan is the difference between nothing and something.
- **Platform/ops engineers** auditing an estate of servers where vendored and
  hand-modified code accumulates outside any repository.
- **Incident responders** asking what on this host could have been the entry
  point.

## Requirements

### Analyse

- R1 [P0] **File discovery** shared with the other subsystems, honouring the
  same paths, skip rules and honesty reporting.
- R2 [P0] **Language detection by extension**, with JavaScript/TypeScript
  (`.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`) as the P0 set.
- R3 [P0] **Line-oriented pattern rules** with per-rule severity, a CWE
  reference, and a human explanation of the consequence — not just a rule name.
- R4 [P1] **Context gating.** A rule may require a second signal within a
  configurable window: `exec` is interesting; `exec` on the same line as
  `req.body` is much more so. This is the mechanism by which a pattern scanner
  earns a `high` rather than a `medium`.
- R5 [P1] **Vendored and generated code is ranked down, not skipped.** A
  vulnerability in `vendor/` still executes; it is simply less likely to be the
  operator's to fix. `deps/` already covers third-party packages by version.
- R6 [P2] Additional languages: Python, PHP, Go, Ruby.

### Rules (P0 set)

- R7 [P0] **Code execution**: `eval`, `new Function`, `vm.runInThisContext`,
  `child_process.exec`/`execSync` with interpolation.
- R8 [P0] **Injection**: SQL built by concatenation or template literal;
  command strings assembled from variables.
- R9 [P0] **Unsafe rendering**: `dangerouslySetInnerHTML`, `innerHTML`,
  `document.write` with a non-literal argument.
- R10 [P0] **Broken transport and crypto**: `rejectUnauthorized: false`,
  `NODE_TLS_REJECT_UNAUTHORIZED = 0`, `md5`/`sha1` for passwords,
  `Math.random()` used for tokens or ids.
- R11 [P1] **Path traversal**: `fs` calls whose argument derives from a request
  field without normalisation.
- R12 [P1] **Deserialisation and prototype pollution**: unsafe YAML load,
  `Object.assign` onto a prototype, merge helpers over user input.

### Report

- R13 [P0] **Confidence on every finding**: `pattern` (the construct exists),
  `contextual` (a dangerous construct with an untrusted-looking source nearby).
  Severity is a function of both rule severity and confidence — a `pattern`
  finding may never exceed `medium`.
- R14 [P0] **Suppression comments**: an inline `threatcrush-disable-next-line
  <rule>` with a required reason. Suppressions are counted and reported, so a
  codebase cannot quietly silence the scanner.
- R15 [P1] Dedupe per (file, rule, code fingerprint) so refactors that move a
  line do not re-alert.
- R16 [P1] `threatcrush scan ./src --fail-on high` for CI use.

## UX Notes

Ships as the `sast` subsystem of `code-scanner`, configured under `sast_*`.

```bash
threatcrush scan ./src                       # one-shot
threatcrush code-scanner sast rules          # every rule, severity and CWE
threatcrush code-scanner sast explain js-eval-call
```

```toml
[code-scanner.sast]
enabled = true
languages = ["javascript", "typescript"]
vendored = "rank_down"
min_confidence = "pattern"     # pattern | contextual
```

```
[HIGH] code-scanner · sast · command injection risk

  /srv/app/routes/admin.ts:52   js-exec-interpolation  (CWE-78)
  exec(`convert ${req.body.file} out.png`)

  confidence: contextual — request data on the same line as a shell exec
  A shell metacharacter in `file` runs as the server user.
```

Design constraints:

- **Never claim proof from a pattern.** The word "vulnerability" is reserved for
  `contextual` findings and above; a bare pattern match is a "risk" or a
  "dangerous construct".
- **Show the line.** A SAST finding an operator cannot see is a finding they
  cannot triage. Source excerpts are shown for this subsystem — unlike
  `secrets`, where showing the match would leak the credential.
- **Say what happens if it is real**, not just which rule fired.

## Success Metrics

- **Zero findings** on a freshly scaffolded Express/Next.js app. The acceptance
  test for staying switched on.
- **100% recall** on a fixture set containing one deliberate instance of every
  P0 rule.
- **No finding above `medium`** carries only `pattern` confidence — asserted by
  test, because this is the overclaiming failure mode and it must be structural
  rather than a matter of care.
- Suppression count is reported on every scan; a scan reporting 0 findings and
  200 suppressions must not read as clean.
- 50k source files in <60s on one core.

## Risks & Open Questions

- **Overclaiming is the existential risk for this subsystem.** A regex is not
  data-flow analysis, and a tool that blurs the two is worse than no tool: it
  produces confident-sounding findings that waste triage time and, when
  disproven, discredit the accurate findings alongside them. R13's confidence
  levels and the metric asserting `pattern` findings stay ≤ medium are the
  structural defences. **Open:** should `pattern`-only findings be off by
  default, surfacing only on explicit request?
- **Vendored code will dominate raw counts.** `node_modules` is excluded by the
  shared walk, but vendored directories, bundled assets and generated code are
  not always distinguishable from first-party source. Ranking down (R5) helps;
  misclassification will still happen.
- **Rule maintenance is unbounded.** Every framework has its own sinks. This is
  precisely why Semgrep has a rule registry and a team. A small hand-maintained
  set that is *honest about being small* is sustainable; ambition here is not.
- **Suppression comments will be abused.** Requiring a reason (R14) and counting
  them is a mitigation, not a fix. **Open:** should a suppression expire, or
  require a date?
- **Overlap with `secrets/` and `deps/`.** A hardcoded key found by a SAST rule
  should be reported by `secrets`, and a vulnerable library by `deps`. Rules
  here must stay out of both to avoid double-reporting the same issue in two
  voices.
