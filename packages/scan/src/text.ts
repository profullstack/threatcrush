/**
 * The scan engine, minus the filesystem: run every rule set over text.
 *
 * Kept free of I/O entirely — no reading, no printing, no exit codes, no
 * SARIF. The command layer decides how to present what this returns, which is
 * what lets the same scan feed a terminal, a SARIF file and a daemon run
 * without three implementations drifting apart.
 *
 * The absence of `node:` imports here is load-bearing, not incidental. This
 * module is the package's default entry point, and the browser surfaces —
 * web, extension, desktop renderer — import it directly. A single
 * `import … from 'node:fs'` anywhere in this file's dependency graph breaks
 * every one of their bundles, so the tree walker lives in `./node/walk.ts`
 * and everything here works on strings that somebody else read.
 */

import { CODE_RULES, evaluateRule, proseLines } from './code-rules';
import { scanPackageJson, scanRequirementsTxt } from './manifest-rules';
import {
  describesItsOwnKey,
  isKnownPlaceholder,
  isPlaceholderAttribute,
  isTestFixtureValue,
  isVariableReference,
  redactSecret,
  SECRET_RULES,
} from './secret-rules';
import { evaluateTemplateRules, TEMPLATE_EXTENSIONS } from './template-rules';
import type { ScanFinding, ScanLanguage, Severity } from './types';
import { severityRank } from './types';

/**
 * `extname` and `basename`, reimplemented in three lines each.
 *
 * Importing them from `node:path` is what would otherwise put this module —
 * and therefore the package's whole default entry point — out of reach of a
 * browser bundle, for two functions that are pure string arithmetic.
 *
 * Semantics match the originals on the inputs that reach them: a leading dot
 * is not an extension, so `.env` has none, and a name with no dot has none
 * either. Only `/` is treated as a separator, which is what the callers pass —
 * repository-relative paths and shebang interpreter paths.
 */
function baseNameOf(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

function extensionOf(path: string): string {
  const base = baseNameOf(path);
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? '' : base.slice(dot);
}

export const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.nuxt', 'dist', 'build', 'out', '__pycache__',
  '.venv', 'venv', 'vendor', '.terraform', 'coverage', '.cache', '.pnpm-store',
  'target', '.gradle', '.idea', '.vscode', 'bower_components', '.svelte-kit',
]);

export const SCAN_EXTENSIONS = new Set([
  '.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
  '.py', '.rb', '.go', '.java', '.kt', '.scala', '.php', '.rs',
  '.c', '.cc', '.cpp', '.h', '.hpp', '.cs', '.swift',
  '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.conf', '.env',
  '.sh', '.bash', '.zsh', '.tf', '.hcl', '.xml', '.properties', '.gradle',
  '.txt', '.md', '.sql', '.erb', '.ejs', '.vue', '.svelte',
  // Template files, so the engine in `template-rules.ts` has something to
  // read. Sourced from the rules themselves rather than repeated here: an
  // engine added there becomes scannable without a second edit that could be
  // forgotten, which is how a rule ends up quietly never firing.
  ...TEMPLATE_EXTENSIONS,
]);

const LANGUAGE_BY_EXTENSION: Record<string, ScanLanguage> = {
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.vue': 'javascript', '.svelte': 'javascript', '.ejs': 'javascript',
  '.py': 'python',
  '.rb': 'ruby', '.erb': 'ruby',
  '.go': 'go',
  '.java': 'java', '.kt': 'java', '.scala': 'java',
  '.php': 'php',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
  '.yml': 'config', '.yaml': 'config', '.json': 'config', '.toml': 'config',
  '.ini': 'config', '.cfg': 'config', '.conf': 'config', '.env': 'config',
  '.tf': 'config', '.hcl': 'config', '.properties': 'config',
};

export function languageOf(filename: string): ScanLanguage {
  if (filename.startsWith('.env') || filename.endsWith('.env')) return 'config';
  return LANGUAGE_BY_EXTENSION[extensionOf(filename).toLowerCase()] ?? 'other';
}

/** Interpreters worth recognising, by the language their scripts are written in. */
const LANGUAGE_BY_INTERPRETER: Record<string, ScanLanguage> = {
  sh: 'shell', bash: 'shell', zsh: 'shell', dash: 'shell', ksh: 'shell', ash: 'shell',
  python: 'python', python2: 'python', python3: 'python',
  ruby: 'ruby',
  node: 'javascript', nodejs: 'javascript', deno: 'javascript', bun: 'javascript',
  php: 'php',
};

/**
 * The language a `#!` line declares, or `null` if the line is not a shebang.
 *
 * An executable in a repository root is routinely named for the command it
 * provides rather than the language it is written in — `debtap`, `configure`,
 * `gradlew`. Extension-based detection skips every one of them, which is worst
 * exactly where it matters: a project whose entire source is one extensionless
 * script gets a clean scan because nothing was read.
 *
 * The shebang is the authoritative answer to a question the filename cannot
 * answer, and the kernel already treats it that way.
 */
export function languageOfShebang(firstLine: string): ScanLanguage | null {
  const match = /^#!\s*(\S+)(?:\s+(.+?))?\s*$/.exec(firstLine);
  if (!match) return null;

  // `#!/usr/bin/env bash` names the interpreter in the argument, not the path.
  const command = baseNameOf(match[1]!);
  const args = match[2]?.trim().split(/\s+/) ?? [];
  const splitString = args[0] === '-S' || args[0] === '--split-string';
  const name = command === 'env' ? baseNameOf(args[splitString ? 1 : 0] ?? '') : command;

  const exact = LANGUAGE_BY_INTERPRETER[name];
  if (exact) return exact;

  // `python3.11` and `bash5` are the same interpreters with a version glued on.
  const stripped = name.replace(/[\d.]+$/, '');
  return (stripped ? LANGUAGE_BY_INTERPRETER[stripped] : undefined) ?? null;
}


/**
 * Inline suppression, matching the convention `modules/code-scanner` already
 * uses so a repository does not learn two syntaxes for the same idea.
 *
 *     // threatcrush-disable-next-line secret-aws-access-key  fixture, not a key
 *     // threatcrush-disable-line
 *
 * The rule id is optional; without one the whole line is suppressed. This
 * exists because the highest-volume false positive in practice is a scanner's
 * own test fixtures — a file of deliberately-malformed credentials is
 * indistinguishable from a file of leaked ones, and only the author knows
 * which. Suppressions are counted and reported: a quiet scan full of
 * suppressions is not a clean one.
 */
const SUPPRESS_NEXT = /threatcrush-disable-next-line(?:\s+([\w-]+))?/;
const SUPPRESS_LINE = /threatcrush-disable-line(?:\s+([\w-]+))?/;

/**
 * Another linter's suppression, naming the linter that means "security" in that
 * linter's own vocabulary.
 *
 * A repository that has already triaged a finding did so in the one place a
 * reviewer will look, which is the line itself. Re-raising it at full severity
 * asks the operator to make the same decision a second time in a different
 * tool, and printing an excerpt whose own text reads "G101 false positive:
 * HTTP header name, not a credential" is the clearest possible signal that
 * nothing read it.
 *
 * This used to insist the *rule* be named — `gosec` and `G101` both. That was
 * the wrong half of the annotation to key on, and it is the single biggest
 * source of noise on a mature Go repository. Measured on mulgadc/spinifex:
 * nine of its twenty-one `InsecureSkipVerify` lines carry a bare
 * `//nolint:gosec` with a written reason beside it —
 *
 *     InsecureSkipVerify: true, //nolint:gosec // self-signed per-node certs
 *
 * — and every one was re-reported at high. Go projects overwhelmingly write the
 * bare form; requiring `G101` meant honouring the annotation almost nowhere it
 * is actually written, while claiming in the docstring to honour it.
 *
 * Naming the *linter* is still required, and that is what keeps this from
 * becoming a way to hide findings. `gosec` and `nosec` are a security linter
 * and its inline directive: a line carrying one has been looked at by a human
 * asking a security question. A bare `//nolint` is a statement about something,
 * with no reason to think it is about security at all, and `//nolint:errcheck`
 * is a statement about error handling. Neither counts.
 *
 * And the finding is downgraded rather than dropped, the way `isTestPath`
 * downgrades a fixture, so it stays in the report for anyone auditing the
 * suppressions themselves.
 */
const FOREIGN_SECURITY = /\b(?:nolint:[\w,]*gosec|nosec)\b/;

export function foreignSecurityMark(line: string): boolean {
  return FOREIGN_SECURITY.test(line);
}

export interface Suppressions {
  /** line index → set of rule ids, or `*` for every rule. */
  byLine: Map<number, Set<string>>;
  count: number;
}

export function collectSuppressions(lines: readonly string[]): Suppressions {
  const byLine = new Map<number, Set<string>>();
  let count = 0;

  const add = (index: number, ruleId: string | undefined): void => {
    const existing = byLine.get(index) ?? new Set<string>();
    existing.add(ruleId ?? '*');
    byLine.set(index, existing);
    count += 1;
  };

  lines.forEach((line, index) => {
    const next = SUPPRESS_NEXT.exec(line);
    if (next) add(index + 1, next[1]);
    const same = SUPPRESS_LINE.exec(line);
    // `disable-next-line` also matches the `disable-line` substring, so only
    // treat it as a same-line directive when the longer form did not match.
    if (same && !next) add(index, same[1]);
  });

  return { byLine, count };
}

function isSuppressed(suppressions: Suppressions, index: number, ruleId: string): boolean {
  const rules = suppressions.byLine.get(index);
  if (!rules) return false;
  return rules.has('*') || rules.has(ruleId);
}

/**
 * Does this path hold tests or fixtures?
 *
 * Used to soften credential findings, never to hide them. A secret in a test
 * is nearly always a fixture — often a deliberately real-looking one, because
 * the test exists to prove the real path is guarded — but "nearly always" is
 * not "always", and a genuine key does get pasted into a test. So these are
 * still reported, at a severity that does not block a merge, rather than
 * dropped where nobody would ever see them.
 */
export function isTestPath(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, '/');
  return (
    /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|e2e|testdata|testutils?|harness)\//i.test(p) ||
    /(?:^|\/)(?:test|conftest)_[^/]+$/i.test(p) ||
    /[._-](?:test|spec)\.[a-z]+$/i.test(p) ||
    /_test\.[a-z]+$/i.test(p)
  );
}

/**
 * Rust source with its comments, strings and char literals blanked out.
 *
 * Brace counting is how the next function finds where a test module ends, and
 * raw braces are everywhere in ordinary Rust that is not a block: `format!("{}",
 * x)` is on more lines than most constructs this engine looks for. Counting
 * those would close a module early and leave the rest of its tests reporting at
 * full severity, which is the bug being fixed here wearing a different hat.
 *
 * Blanking rather than deleting keeps every column where it was, so a line's
 * index and the offsets inside it still line up with the original text.
 *
 * Rust-specific in three ways a generic stripper gets wrong: block comments
 * nest, so the first close does not necessarily end one; raw strings suspend
 * escaping and close only on a quote followed by as many hashes as opened them
 * (`r#"a "quoted" string"#`); and a lone `'` is far more often a lifetime
 * (`&'a str`) than the start of a char literal.
 */
function rustCodeLines(lines: readonly string[]): string[] {
  const out: string[] = [];
  let commentDepth = 0;
  let str: { raw: boolean; hashes: number } | null = null;

  for (const line of lines) {
    let code = '';
    let i = 0;

    while (i < line.length) {
      const c = line[i]!;
      const d = line[i + 1];

      if (commentDepth > 0) {
        if (c === '*' && d === '/') { commentDepth -= 1; code += '  '; i += 2; continue; }
        if (c === '/' && d === '*') { commentDepth += 1; code += '  '; i += 2; continue; }
        code += ' '; i += 1; continue;
      }

      if (str) {
        if (str.raw) {
          if (c === '"') {
            let hashes = 0;
            while (line[i + 1 + hashes] === '#') hashes += 1;
            if (hashes >= str.hashes) {
              code += ' '.repeat(1 + str.hashes);
              i += 1 + str.hashes;
              str = null;
              continue;
            }
          }
          code += ' '; i += 1; continue;
        }
        // A backslash escapes the next character, a closing quote included.
        if (c === '\\') { code += '  '; i += 2; continue; }
        if (c === '"') { str = null; code += ' '; i += 1; continue; }
        code += ' '; i += 1; continue;
      }

      if (c === '/' && d === '/') { code += ' '.repeat(line.length - i); break; }
      if (c === '/' && d === '*') { commentDepth = 1; code += '  '; i += 2; continue; }

      // `r"…"`, `r#"…"#`, `br##"…"##` — but only where `r` opens a token, so
      // the `r` ending an identifier cannot be read as a raw string prefix.
      if (i === 0 || !/[A-Za-z0-9_]/.test(line[i - 1]!)) {
        const raw = /^b?r(#*)"/.exec(line.slice(i));
        if (raw) {
          str = { raw: true, hashes: raw[1]!.length };
          code += ' '.repeat(raw[0].length);
          i += raw[0].length;
          continue;
        }
      }

      if (c === '"') { str = { raw: false, hashes: 0 }; code += ' '; i += 1; continue; }

      if (c === "'") {
        const char = /^'(?:\\.|[^\\'])'/.exec(line.slice(i));
        if (char) { code += ' '.repeat(char[0].length); i += char[0].length; continue; }
        // A lifetime. Nothing to blank, and no string was opened.
        code += c; i += 1; continue;
      }

      code += c;
      i += 1;
    }

    out.push(code);
  }

  return out;
}

/** `not(test)` gates code compiled when tests are *off* — the opposite of a test block. */
const RUST_CFG_NOT_TEST = /\bnot\s*\(\s*test\s*\)/;

/** `#[test]`, `#[tokio::test]`, `#[rstest]`, `#[bench]` — an item only tests run. */
const RUST_TEST_ITEM_ATTRIBUTE =
  /^\s*#\s*\[\s*(?:[A-Za-z_]\w*\s*::\s*)*(?:test|bench|rstest|proptest|quickcheck|test_case)\b/;

/**
 * Does this (already blanked) line open an item that exists only under `cargo test`?
 *
 * The string blanking is what lets the `cfg` arm be written this loosely:
 * `#[cfg(feature = "test-util")]` arrives here as `#[cfg(feature = "        ")]`,
 * so a feature flag that merely has "test" in its name is not read as a gate.
 */
function isRustTestAttribute(code: string): boolean {
  if (RUST_CFG_NOT_TEST.test(code)) return false;
  if (/^\s*#\s*\[\s*cfg\s*\(/.test(code)) return /\btest\b/.test(code);
  return RUST_TEST_ITEM_ATTRIBUTE.test(code);
}

/** The last line of the item beginning at `start`, by brace depth. */
function rustItemEnd(code: readonly string[], start: number): number {
  let depth = 0;
  let opened = false;

  for (let i = start; i < code.length; i += 1) {
    for (const ch of code[i]!) {
      if (ch === '{') {
        depth += 1;
        opened = true;
      } else if (ch === '}') {
        depth -= 1;
        if (opened && depth <= 0) return i;
      } else if (ch === ';' && !opened && depth === 0) {
        // A declaration rather than a block: `#[cfg(test)] mod tests;`.
        return i;
      }
    }
  }

  // Unbalanced — a truncated file, or a brace this stripper misread. Claiming
  // the rest of the file would soften production code on the strength of a
  // parse that has already gone wrong, so claim only what was certain.
  return start;
}

const NO_INLINE_TESTS: ReadonlySet<number> = new Set<number>();

/**
 * The lines of a file that hold tests living *inside* it.
 *
 * `isTestPath` asks where a file sits, which is the whole answer in Go, Python
 * and JavaScript, where tests occupy files of their own. Rust puts unit tests in
 * the same file as the code they cover, behind `#[cfg(test)]` — so a path rule
 * can never reach them, and every fixture password in every `mod tests` reports
 * at full severity from what is, by construction, test code.
 *
 * Measured on ferriskey/ferriskey (Rust IAM, 689 stars) at 0.11.8: 135 findings,
 * zero true positives, of which 15 are exactly this. The sharpest is a fixture
 * password assigned in a `#[tokio::test]` at `core/src/domain/trident/
 * services.rs:2719`, whose `#[cfg(test)]` opens at 2137 of 4042 lines — so the
 * block covers only the second half of the file, and neither half can be spelled
 * into `isTestPath` without taking the other with it. That is the whole reason
 * this is keyed on lines rather than on the path.
 *
 * Returns 0-based line indices, and only for Rust — the one language measured to
 * need it. Go's toolchain will not run a test outside a `_test.go` file, and
 * Python and JavaScript convention give tests their own files; `isTestPath`
 * already reads all three.
 */
export function inlineTestLines(relativePath: string, lines: readonly string[]): ReadonlySet<number> {
  if (extensionOf(relativePath).toLowerCase() !== '.rs') return NO_INLINE_TESTS;

  const code = rustCodeLines(lines);
  const inside = new Set<number>();

  for (let i = 0; i < code.length; i += 1) {
    // Attributes on the tests *within* an already-claimed module add nothing.
    if (inside.has(i) || !isRustTestAttribute(code[i]!)) continue;
    const end = rustItemEnd(code, i);
    for (let j = i; j <= end; j += 1) inside.add(j);
  }

  return inside;
}

/**
 * Does this path hold documentation or illustrative code?
 *
 * The same softening as `isTestPath`, and for the *code* rules only. A fenced
 * block in a README is a transcript of a command someone might run, not a
 * program that runs: `go run . -log-dir /tmp/artifacts` in a usage example is
 * not a symlink attack on anybody, because nothing executes it.
 *
 * Deliberately not applied to the credential rules, which is the opposite of
 * what the volume on a documentation tree first suggests. Their noise is a
 * property of the *value*, and value is the axis they are keyed on:
 * `limen-regression.test.ts` pins a README quoting `postgres://user:pass@host`
 * as silent while a real DSN in that same README still reports at `high`, and a
 * path rule would give that up. A README is a perfectly ordinary place to leak
 * a key.
 *
 * mulgadc/spinifex matches the AWS key rule ninety-six times. Ninety of those
 * are in test paths and were already `low`; the remaining six are in `docs/`,
 * and they are every critical left on that repository after this change. See
 * the note in `secret-rules.ts` on typed sequences for why the value-side fix
 * that would have silenced them cannot be had without giving up real detection.
 */
export function isDocPath(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, '/');
  return (
    /(?:^|\/)(?:docs?|examples?|samples?)\//i.test(p) ||
    /\.(?:md|mdx|markdown|rst|adoc)$/i.test(p)
  );
}

/**
 * Why a finding is being reported at `low` rather than at its rule's severity.
 *
 * Five contexts, one mechanism. Each says something about the *setting* of a
 * match rather than about the construct itself, so none of them may ever drop
 * a finding — a softened finding is still counted, still printed, still in the
 * SARIF, and `--fail-on low` still stops on it. The severity is the claim being
 * weakened, not the report.
 *
 * That is the line this must not cross. Every one of these is a heuristic about
 * where code lives or what it is named, and heuristics of that kind are wrong
 * often enough that they may inform a severity and never a verdict.
 */
type Softening = 'test' | 'test-block' | 'docs' | 'suppressed' | 'placeholder' | 'self-describing';

/** Most specific evidence first, so it is the reason the operator is shown. */
const SOFTENING_ORDER: readonly Softening[] = [
  'suppressed',
  'placeholder',
  'self-describing',
  // Before `test`, because it is the narrower claim: a path holds tests, but a
  // block *is* one. A Rust file under `tests/` can be both.
  'test-block',
  'test',
  'docs',
];

function softening(reasons: Partial<Record<Softening, boolean>>): Softening | null {
  return SOFTENING_ORDER.find((reason) => reasons[reason]) ?? null;
}

/** The clause completing "Possible AWS Access Key detected …" on a secret. */
const SECRET_SOFTENING: Record<Softening, string> = {
  test: 'in a test file — usually a fixture, still worth confirming it is not a live credential',
  'test-block':
    'in a test-only block — usually a fixture, still worth confirming it is not a live credential',
  docs: 'in documentation — usually an illustrative example, still worth confirming it is not a live credential',
  suppressed: "on a line already marked as a false positive for another linter's security rule",
  placeholder: 'in example text an empty input field shows, not in data',
  'self-describing':
    'in a value that repeats the name of the field holding it — usually a description of a credential rather than one',
};

/** The clause appended to a code finding's message to say why it was softened. */
const CODE_SOFTENING: Record<Softening, string> = {
  test: 'in a test file, where the construct is ordinary',
  'test-block': 'in a test-only block, where the construct is ordinary',
  docs: 'in documentation or example code, which nothing runs',
  suppressed: "on a line another linter's security suppression already covers",
  placeholder: 'in example text rather than in data',
  'self-describing': 'in a value that describes itself',
};

/** Scan a single file's text. Exposed for tests and for single-file callers. */
export function scanText(
  relativePath: string,
  text: string,
  language: ScanLanguage = languageOf(relativePath),
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = text.split('\n');
  const suppressions = collectSuppressions(lines);
  const inTests = isTestPath(relativePath);
  const inDocs = isDocPath(relativePath);
  const inlineTests = inlineTestLines(relativePath, lines);

  // ── Credentials ────────────────────────────────────────────────────────
  lines.forEach((line, index) => {
    for (const rule of SECRET_RULES) {
      const match = rule.pattern.exec(line);
      if (!match) continue;
      if (isKnownPlaceholder(match[0])) continue;
      if (isSuppressed(suppressions, index, rule.id)) continue;

      // The value the rule actually captured, falling back to the whole match
      // for the vendor-prefixed rules, which have no capture group because the
      // format *is* the value.
      const value = match[1] ?? match[0];

      // An expansion is not a literal, in a test file or anywhere else.
      if (isVariableReference(value)) continue;

      // Fixtures, and only in files that are fixtures by construction. See
      // `isTestFixtureValue` for why this cannot reach a vendor-issued key.
      if (inTests && rule.keywordShaped && isTestFixtureValue(line, value)) continue;

      // A value that repeats its own key is a description of a credential
      // rather than one — and unlike the fixture exemption above, that is true
      // outside a test too, so it softens rather than skips. See
      // `describesItsOwnKey`.
      //
      // Note the `false` where the code rules below pass `inDocs`. Documentation
      // noise is a *value* problem for the credential rules and is solved by
      // `isKnownPlaceholder`, deliberately: `limen-regression.test.ts` pins the
      // behaviour that a README quoting `postgres://user:pass@host` is silent
      // while a real DSN in the same README is still `high`. Softening secrets
      // by path would take that guarantee away, and a README is a perfectly
      // ordinary place to leak a key.
      // Note that the fixture *exemption* above stays keyed on `inTests` alone.
      // That one drops a finding, and dropping is a verdict; a block boundary
      // this engine inferred from brace counting is evidence for a severity and
      // not for silence. An inline test block softens, and only softens.
      const soft = softening({
        test: inTests,
        'test-block': inlineTests.has(index),
        suppressed: foreignSecurityMark(line),
        placeholder: isPlaceholderAttribute(line, value),
        'self-describing': rule.keywordShaped === true && describesItsOwnKey(line, value),
      });

      findings.push({
        ruleId: rule.id,
        title: rule.name,
        file: relativePath,
        line: index + 1,
        // Reported but not blocking wherever context weakens the claim — see
        // `softening`. Never dropped: the count is the same either way.
        severity: soft ? 'low' : rule.severity,
        // A matched credential format is the finding, not a proxy for one.
        confidence: 'evidence',
        message: soft
          ? `Possible ${rule.name} detected ${SECRET_SOFTENING[soft]}`
          : `Possible ${rule.name} detected`,
        consequence: rule.consequence,
        cwe: rule.cwe,
        excerpt: redactSecret(line.trim()).slice(0, 200),
        sensitive: true,
        category: 'secret',
      });
    }
  });

  // ── Code-level constructs ──────────────────────────────────────────────
  const prose = proseLines(lines);
  lines.forEach((_line, index) => {
    for (const rule of CODE_RULES) {
      if (isSuppressed(suppressions, index, rule.id)) continue;
      const match = evaluateRule(rule, { lines, index, language, prose });
      if (!match) continue;

      // The context the credential rules above have always read, applied to the
      // code rules for the first time. Leaving it off them was the second of
      // the three structural false-positive causes and much the largest: on
      // mulgadc/spinifex it is 104 findings, every one of them a code rule
      // reporting at full severity from inside a test — `"/tmp/test-wal"` in a
      // table-driven fixture, `exec.Command("sh", "-c", "exit 42")` in a
      // process-supervision test, `InsecureSkipVerify` against the harness's own
      // self-signed certificate. Each is the normal way to write that test.
      const soft = softening({
        test: inTests,
        'test-block': inlineTests.has(index),
        docs: inDocs,
        suppressed: foreignSecurityMark(lines[index] ?? ''),
      });

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        file: relativePath,
        line: index + 1,
        severity: soft ? 'low' : match.severity,
        confidence: match.confidence,
        message: soft ? `${rule.title} (${rule.cwe}) — ${CODE_SOFTENING[soft]}` : `${rule.title} (${rule.cwe})`,
        consequence: rule.consequence,
        cwe: rule.cwe,
        excerpt: (lines[index] ?? '').trim().slice(0, 200),
        category: 'code',
      });
    }
  });

  // ── Template output ────────────────────────────────────────────────────
  //
  // Keyed on the extension rather than on `language`, because the extension is
  // what names the engine and the engine is what decides which syntax skips
  // escaping. This runs *in addition to* the code rules above, so a `.vue`
  // file is checked both as JavaScript and as a template.
  for (const match of evaluateTemplateRules(extensionOf(relativePath), lines)) {
    const index = match.line - 1;
    if (isSuppressed(suppressions, index, match.rule.id)) continue;

    const soft = softening({
      test: inTests,
      'test-block': inlineTests.has(index),
      docs: inDocs,
      suppressed: foreignSecurityMark(lines[index] ?? ''),
    });

    findings.push({
      ruleId: match.rule.id,
      title: match.rule.title,
      file: relativePath,
      line: match.line,
      severity: soft ? 'low' : match.severity,
      confidence: 'pattern',
      message: soft
        ? `${match.rule.title} (${match.rule.cwe}) — ${CODE_SOFTENING[soft]}`
        : `${match.rule.title} (${match.rule.cwe})`,
      consequence: match.rule.consequence,
      cwe: match.rule.cwe,
      excerpt: (lines[index] ?? '').trim().slice(0, 200),
      category: 'code',
    });
  }

  return findings;
}

export function scanManifest(relativePath: string, filename: string, text: string): ScanFinding[] {
  const manifestFindings =
    filename === 'package.json'
      ? scanPackageJson(text)
      : filename === 'requirements.txt'
        ? scanRequirementsTxt(text)
        : [];

  return manifestFindings.map((finding) => ({
    ruleId: finding.ruleId,
    title: finding.title,
    file: relativePath,
    line: finding.line,
    severity: finding.severity,
    confidence: 'evidence' as const,
    message: finding.message,
    consequence: finding.consequence,
    cwe: finding.cwe,
    excerpt: finding.excerpt.slice(0, 200),
    category: 'manifest' as const,
  }));
}



/** Highest severity present, or null for a clean scan. */
export function peakSeverity(findings: readonly ScanFinding[]): Severity | null {
  let peak: Severity | null = null;
  for (const finding of findings) {
    if (!peak || severityRank(finding.severity) > severityRank(peak)) peak = finding.severity;
  }
  return peak;
}

/** True when any finding is at or above `threshold`. Drives `--fail-on`. */
export function meetsFailThreshold(
  findings: readonly ScanFinding[],
  threshold: readonly Severity[],
): boolean {
  if (threshold.length === 0) return false;
  const floor = Math.min(...threshold.map(severityRank));
  return findings.some((finding) => severityRank(finding.severity) >= floor);
}
