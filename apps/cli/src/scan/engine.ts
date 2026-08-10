/**
 * The scan engine: walk a tree, run every rule set over it, return findings.
 *
 * Kept free of any I/O beyond reading files — no printing, no exit codes, no
 * SARIF. The command layer decides how to present what this returns, which is
 * what lets the same scan feed a terminal, a SARIF file and a daemon run
 * without three implementations drifting apart.
 */

import {
  closeSync, fstatSync, openSync, readdirSync, readFileSync, readSync, statSync,
} from 'node:fs';
import { basename, dirname, extname, join, relative, sep } from 'node:path';
import { CODE_RULES, evaluateRule, proseLines } from './code-rules.js';
import { scanPackageJson, scanRequirementsTxt } from './manifest-rules.js';
import { isKnownPlaceholder, redactSecret, SECRET_RULES, SENSITIVE_FILES } from './secret-rules.js';
import type { ScanFinding, ScanLanguage, Severity } from './types.js';
import { severityRank } from './types.js';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.nuxt', 'dist', 'build', 'out', '__pycache__',
  '.venv', 'venv', 'vendor', '.terraform', 'coverage', '.cache', '.pnpm-store',
  'target', '.gradle', '.idea', '.vscode', 'bower_components', '.svelte-kit',
]);

const SCAN_EXTENSIONS = new Set([
  '.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
  '.py', '.rb', '.go', '.java', '.kt', '.scala', '.php', '.rs',
  '.c', '.cc', '.cpp', '.h', '.hpp', '.cs', '.swift',
  '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.conf', '.env',
  '.sh', '.bash', '.zsh', '.tf', '.hcl', '.xml', '.properties', '.gradle',
  '.txt', '.md', '.sql', '.erb', '.ejs', '.vue', '.svelte',
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
  return LANGUAGE_BY_EXTENSION[extname(filename).toLowerCase()] ?? 'other';
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
  const command = basename(match[1]!);
  const args = match[2]?.trim().split(/\s+/) ?? [];
  const splitString = args[0] === '-S' || args[0] === '--split-string';
  const name = command === 'env' ? basename(args[splitString ? 1 : 0] ?? '') : command;

  const exact = LANGUAGE_BY_INTERPRETER[name];
  if (exact) return exact;

  // `python3.11` and `bash5` are the same interpreters with a version glued on.
  const stripped = name.replace(/[\d.]+$/, '');
  return (stripped ? LANGUAGE_BY_INTERPRETER[stripped] : undefined) ?? null;
}

export interface ScanOptions {
  /** Skip files larger than this. Defaults to 1 MiB. */
  maxFileBytes?: number;
  /** Called once per file actually read, for progress reporting. */
  onFile?: (path: string) => void;
  /** Restrict to these rule categories. Defaults to all. */
  categories?: readonly ScanFinding['category'][];
}

export interface ScanReport {
  findings: ScanFinding[];
  filesScanned: number;
  /**
   * How many inline suppressions were honoured. Reported, never hidden: a
   * scan that came back quiet because someone silenced forty rules is a
   * different result from a scan that came back quiet.
   */
  suppressed: number;
  /**
   * Directory that finding paths are relative to. Equal to the target for a
   * directory scan, its parent for a single-file scan. SARIF URI resolution
   * needs this — guessing it from the target is what produces file URIs that
   * resolve to nothing.
   */
  root: string;
  /**
   * Files matched by extension but unreadable. Reported rather than swallowed:
   * a scan that could not read a file has not cleared it, and "0 findings"
   * over an unread tree is the failure this scanner exists to avoid.
   */
  unreadable: string[];
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

      findings.push({
        ruleId: rule.id,
        title: rule.name,
        file: relativePath,
        line: index + 1,
        // Reported but not blocking in tests — see isTestPath.
        severity: inTests ? 'low' : rule.severity,
        // A matched credential format is the finding, not a proxy for one.
        confidence: 'evidence',
        message: inTests
          ? `Possible ${rule.name} detected in a test file — usually a fixture, still worth confirming it is not a live credential`
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

  return findings;
}

function scanManifest(relativePath: string, filename: string, text: string): ScanFinding[] {
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

export function scanPath(targetPath: string, options: ScanOptions = {}): ScanReport {
  const maxFileBytes = options.maxFileBytes ?? 1024 * 1024;
  const allowed = options.categories ? new Set(options.categories) : null;
  const findings: ScanFinding[] = [];
  const unreadable: string[] = [];
  let filesScanned = 0;
  let suppressed = 0;

  // A file target is not a degenerate directory target. `readdirSync` on a
  // file throws ENOTDIR, which the walker below treats as an unreadable
  // directory — so `threatcrush scan app.js` reported a clean scan of a file
  // it never opened. Resolve the shape first, and walk only what is walkable.
  const rootIsDirectory = (() => {
    try {
      return statSync(targetPath).isDirectory();
    } catch {
      return true;
    }
  })();
  const walkRoot = rootIsDirectory ? targetPath : dirname(targetPath);

  const scanFile = (fullPath: string, filename: string): void => {
    const relativePath = toRelative(walkRoot, fullPath);
    const extension = extname(filename).toLowerCase();
    const isManifest = filename === 'package.json' || filename === 'requirements.txt';
    const scannable = SCAN_EXTENSIONS.has(extension) || filename.startsWith('.env');

    // A file with no extension gets one question asked of it before being
    // dismissed: does it start with a shebang? Executables are habitually named
    // for what they do rather than what they are written in, and skipping them
    // silently is how a repository whose only source file is `debtap` scans
    // clean. Files that carry an unrecognised extension are still skipped —
    // `.png` is not a script, and sniffing every one of them would mean reading
    // the whole tree.
    const mayDeclareInterpreter = !scannable && !isManifest && extension === '';

    if (!scannable && !isManifest && !mayDeclareInterpreter) {
      recordSensitiveFile(filename, relativePath, findings, []);
      return;
    }

    // Size-check and read through one descriptor.
    //
    // `statSync(path)` followed by `readFileSync(path)` is check-then-use: the
    // path can be replaced between the two calls, so the size that was checked
    // is not necessarily the size that gets read. Opening once and calling
    // `fstatSync` on the descriptor removes the window — the descriptor refers
    // to the same inode for both operations, whatever happens to the name.
    //
    // A scanner walking directories it does not control is exactly where this
    // matters, and CWE-362 is a class this tool reports on. Worth getting
    // right in its own walker.
    let text: string;
    let handle: number;
    let declared: ScanLanguage | null = null;
    try {
      handle = openSync(fullPath, 'r');
    } catch {
      unreadable.push(relativePath);
      return;
    }

    try {
      if (fstatSync(handle).size > maxFileBytes) return;

      // Sniff the shebang from a short prefix rather than the whole file, so an
      // extensionless blob — a checked-in binary, a data file — costs one small
      // read instead of a megabyte decoded as UTF-8 and thrown away.
      if (mayDeclareInterpreter) {
        const prefix = Buffer.alloc(128);
        const read = readSync(handle, prefix, 0, prefix.length, 0);
        declared = languageOfShebang(prefix.subarray(0, read).toString('utf-8').split('\n', 1)[0] ?? '');
        if (!declared) return;
      }

      text = readFileSync(handle, 'utf-8');
    } catch {
      unreadable.push(relativePath);
      return;
    } finally {
      try {
        closeSync(handle);
      } catch {
        /* the descriptor is going away regardless */
      }
    }

    filesScanned += 1;
    options.onFile?.(relativePath);
    suppressed += collectSuppressions(text.split('\n')).count;

    const fileFindings = [
      ...scanText(relativePath, text, declared ?? languageOf(filename)),
      ...(isManifest ? scanManifest(relativePath, filename, text) : []),
    ];

    findings.push(...fileFindings);
    recordSensitiveFile(filename, relativePath, findings, fileFindings);
  };

  const walk = (currentPath: string): void => {
    let entries;
    try {
      entries = readdirSync(currentPath, { withFileTypes: true });
    } catch {
      unreadable.push(toRelative(walkRoot, currentPath));
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentPath, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;

      scanFile(fullPath, entry.name);
    }
  };

  if (rootIsDirectory) {
    walk(targetPath);
  } else {
    scanFile(targetPath, basename(targetPath));
  }

  const filtered = allowed ? findings.filter((f) => allowed.has(f.category)) : findings;
  filtered.sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  return { findings: filtered, filesScanned, unreadable, suppressed, root: walkRoot };
}

/**
 * Report a file whose *name* is the finding — but only when its contents
 * produced nothing.
 *
 * A `.env` full of detected credentials does not also need "this is a .env
 * file" stapled to line 1. The filename finding exists for the case the
 * content rules cannot cover: an env file whose values are shapes no vendor
 * rule matches, which is still an env file that should not be committed.
 */
function recordSensitiveFile(
  filename: string,
  relativePath: string,
  sink: ScanFinding[],
  fileFindings: readonly ScanFinding[],
): void {
  if (fileFindings.length > 0) return;

  for (const sensitive of SENSITIVE_FILES) {
    const matches = filename === sensitive.pattern || filename.endsWith(sensitive.pattern);
    if (!matches) continue;
    sink.push({
      ruleId: 'sensitive-file-committed',
      title: 'Sensitive file',
      file: relativePath,
      line: 1,
      severity: sensitive.severity,
      confidence: 'evidence',
      message: sensitive.message,
      consequence: 'Anything in this file is in every clone, fork and CI cache of the repository.',
      cwe: 'CWE-538',
      excerpt: '',
      sensitive: true,
      category: 'file',
    });
    return;
  }
}

function toRelative(base: string, target: string): string {
  const rel = relative(base, target);
  return (rel === '' ? target : rel).split(sep).join('/');
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
