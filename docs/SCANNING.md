# `threatcrush scan`

Static analysis over a directory or a single file: hardcoded credentials,
code-level vulnerability patterns, and dependency-manifest tampering.

```bash
threatcrush scan .                                   # human-readable
threatcrush scan . --format sarif --output out.sarif # for CI and the Security tab
threatcrush scan . --fail-on critical,high           # exit 1 on findings
```

## Options

| Option | Effect |
| --- | --- |
| `-f, --format <text\|json\|sarif>` | Output format. Default `text`. |
| `-o, --output <file>` | Write `json`/`sarif` to a file instead of stdout. |
| `--fail-on <severities>` | Exit `1` when a finding at or above any listed severity exists. Comma-separated. |
| `--path-prefix <prefix>` | Prepend to SARIF file URIs. See *Paths*, below. |
| `--deps` | Also query OSV.dev for advisories against lockfile versions. Network. |
| `-v, --verbose` | List the paths that could not be read, not just the count. |

Exit codes: `0` clean (or findings below the `--fail-on` floor), `1` findings at
or above the floor, `2` the scan itself failed.

When `--format` is not `text`, the payload goes to stdout and every human line
goes to stderr, so `threatcrush scan . --format sarif > out.sarif` produces a
valid file.

## Paths

SARIF URIs are emitted relative to the **working directory**, not the scan
target:

```bash
cd repo && threatcrush scan vulns --format sarif   # → vulns/secrets/x.env
```

This matters more than it looks. A consumer — GitHub's Security tab, a coverage
validator, a PR annotator — resolves URIs against the repository root. Emitting
`secrets/x.env` for a file the repository knows as `vulns/secrets/x.env` makes
every finding land outside whatever the consumer scoped to, and a working scan
reports as zero coverage. It fails silently, and it looks exactly like a clean
scan.

`--path-prefix` covers the one case the working directory cannot: a scan run
from *inside* the directory being scanned.

```bash
cd repo/vulns && threatcrush scan . --format sarif --path-prefix vulns
```

## What it detects

| Category | Covers |
| --- | --- |
| Credentials | Vendor-prefixed key shapes (AWS, GitHub, npm, Slack, Stripe, SendGrid, Google, OpenAI, Anthropic), private keys, database URLs carrying a password, JWTs |
| Injection | SQL (`CWE-89`), OS command (`CWE-78`), dynamic code (`CWE-95`), server-side template (`CWE-1336`) |
| Web | XSS (`CWE-79`), open redirect (`CWE-601`), SSRF (`CWE-918`) |
| Data handling | Unsafe deserialisation (`CWE-502`), XXE (`CWE-611`), path traversal (`CWE-22`), prototype pollution (`CWE-1321`) |
| Crypto & tokens | JWT decoded without verification (`CWE-347`), disabled TLS verification (`CWE-295`), broken hashes on credentials (`CWE-327`), predictable randomness (`CWE-338`), ReDoS (`CWE-1333`) |
| Supply chain | Typosquats and dependency confusion (`CWE-1357`), install-time lifecycle scripts (`CWE-506`), obfuscated code sinks |
| Hygiene | Committed `.env` files and key material (`CWE-538`), stack traces returned to callers (`CWE-209`), environment exfiltration (`CWE-532`) |

Languages: JavaScript, TypeScript, Python, Ruby, Go, Java, plus
language-agnostic rules for credentials and configuration.

## Confidence, and what the severity means

Every finding carries a confidence, because a regex is not data-flow analysis
and a scanner that blurs the two produces confident-sounding findings that
waste triage time.

| Confidence | Claim | Severity |
| --- | --- | --- |
| `pattern` | The dangerous construct is present on the line. Nothing more. | **Capped at medium**, structurally |
| `contextual` | The construct sits alongside something that looks like attacker-controlled input. | Full rule severity |
| `evidence` | The match *is* the finding — a committed credential is committed whether or not a request reaches it. | Full rule severity |

The cap is enforced centrally, so no rule can opt out of it by accident. This
also means `--fail-on critical` will not fire on a bare pattern match: to break
a build, a finding has to be more than "this construct exists".

## Guard windows

A rule can be exonerated by the code around it — an allow-list two lines up, a
`realpath` on the same line, an `ObjectInputFilter` installed before the
`readObject()`. Two exclusions make that work:

- **Comments are not evidence.** A line reading `// no allow-list here` is not
  an allow-list.
- **Definitions are not evidence.** `def sanitize_path(path)` is a name.
  Naming a function `sanitize` does not sanitise anything.

Python docstrings and multi-line strings are excluded from scanning entirely.
A file whose header describes the vulnerability it contains should not produce
findings *about that description*.

## Suppression

```js
// threatcrush-disable-next-line secret-github-token  fixture, not a live token
const token = 'ghp_...';

const key = 'AKIA...'; // threatcrush-disable-line
```

The rule id is optional; without one the whole line is suppressed. Suppressions
are **counted and reported** — a scan that came back quiet because someone
silenced forty rules is a different result from a scan that came back quiet.

## Known gaps

Four classes are deliberately not implemented, because each needs reasoning
this scanner does not do, and the line-oriented approximation of each one flags
ordinary software:

| CWE | Class | Why not |
| --- | --- | --- |
| CWE-352 | Missing CSRF token | Needs to know a handler is state-changing and that no token check dominates the mutation. Line-locally, the vulnerable and the guarded handler are the same code. |
| CWE-362 | Check-then-use race | Needs to pair a check with a later use of the same path. A rule matching either half alone flags every `os.path.exists`. |
| CWE-190 | Integer overflow | Needs range reasoning about the operands. |
| CWE-1321 | Prototype pollution via generic dynamic assignment | `target[key] = source[key]` is both the vulnerable merge and the guarded one. The explicit `__proto__` shapes *are* covered. |

A missing detection is a known number. A rule that fires on every session read
is a scanner nobody runs twice.

## Measured coverage

Scored against [`profullstack/malware-test-prs`][testbed], a corpus of 38 test
cases carrying 93 `VULNERABLE:` markers and a control group of 46 `SAFE:`
lines — each safe line a *correct* implementation of the pattern the
neighbouring vulnerable code gets wrong.

| Metric | Before | Now |
| --- | --- | --- |
| True positive rate | 15.6% (12/77) | **90.32% (84/93)** |
| False positive rate | 0.0% | **0.0% (0/46)** |
| Unattributed findings | 0 | **0** |
| Findings outside corpus | — | **0** |

Reproduce:

```bash
git clone https://github.com/profullstack/malware-test-prs
cd malware-test-prs
threatcrush scan vulns --format sarif --output threatcrush.sarif
python3 scripts/validate-coverage.py \
  --sarif threatcrush.sarif --catalog vulns/VULNERABILITY_CATALOG.json
```

All nine remaining misses are the four classes in *Known gaps* above — nothing
is missed by accident.

Two caveats on reading that number as recall:

1. Every payload in that corpus is wrapped in `if (false)` / `if False:`. This
   scanner matches syntax and is unaffected, but a taint-analysis tool would
   under-report against it. The number is not comparable across tool classes.
2. The corpus's two Slack fixtures are degraded to survive GitHub push
   protection. Validator-backed secret scanners score lower there than they
   would against a real leak.

[testbed]: https://github.com/profullstack/malware-test-prs
