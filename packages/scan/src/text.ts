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
  isKnownPlaceholder,
  isTestFixtureValue,
  isVariableReference,
  redactSecret,
  SECRET_RULES,
  SENSITIVE_FILES,
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
 * Another linter's suppression, naming the rule that means "hardcoded
 * credential" in that linter's own vocabulary.
 *
 * A repository that has already triaged a finding did so in the one place a
 * reviewer will look, which is the line itself. Re-raising it at full severity
 * asks the operator to make the same decision a second time in a different
 * tool, and printing an excerpt whose own text reads "G101 false positive:
 * HTTP header name, not a credential" is the clearest possible signal that
 * nothing read it.
 *
 * Two things keep this from becoming a way to hide real findings. The rule has
 * to be named: a bare `//nolint` is a statement about something, and there is
 * no reason to think it is about credentials. And the finding is downgraded
 * rather than dropped, the way `isTestPath` downgrades a fixture, so it stays
 * in the report for anyone auditing the suppressions themselves.
 */
const FOREIGN_CREDENTIAL = /\b(?:nolint:[\w,]*gosec|nosec)\b[^\n]*\bG101\b|\bG101\b[^\n]*\b(?:nolint:[\w,]*gosec|nosec)\b/;

export function foreignCredentialMark(line: string): boolean {
  return FOREIGN_CREDENTIAL.test(line);
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
    /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|e2e|testdata)\//i.test(p) ||
    /(?:^|\/)(?:test|conftest)_[^/]+$/i.test(p) ||
    /[._-](?:test|spec)\.[a-z]+$/i.test(p) ||
    /_test\.[a-z]+$/i.test(p)
  );
}

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

      const marked = foreignCredentialMark(line);

      findings.push({
        ruleId: rule.id,
        title: rule.name,
        file: relativePath,
        line: index + 1,
        // Reported but not blocking in tests — see isTestPath. The same goes
        // for a line another linter's credential rule was already told about.
        severity: inTests || marked ? 'low' : rule.severity,
        // A matched credential format is the finding, not a proxy for one.
        confidence: 'evidence',
        message: inTests
          ? `Possible ${rule.name} detected in a test file — usually a fixture, still worth confirming it is not a live credential`
          : marked
            ? `Possible ${rule.name} detected on a line already marked as a false positive for another linter's credential rule`
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

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        file: relativePath,
        line: index + 1,
        severity: match.severity,
        confidence: match.confidence,
        message: `${rule.title} (${rule.cwe})`,
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

    findings.push({
      ruleId: match.rule.id,
      title: match.rule.title,
      file: relativePath,
      line: match.line,
      severity: match.severity,
      confidence: 'pattern',
      message: `${match.rule.title} (${match.rule.cwe})`,
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
