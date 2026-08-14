/**
 * Dependency advisory lookup against OSV.dev (PRD 06).
 *
 * Split out of `commands/scan.ts` unchanged in behaviour. It is the only part
 * of a scan that makes network calls, and that difference is worth a module
 * boundary: the pattern rules are deterministic and fast, this is neither, and
 * CI wants to choose. `runScan` keeps calling it (the daemon has always
 * included advisories); the CLI asks for it with `--deps`.
 *
 * The lockfile list and the parser used to disagree. `pnpm-lock.yaml`,
 * `yarn.lock` and `Pipfile.lock` were listed as supported, matched by
 * filename, and then fell through a parser that only implemented
 * `package-lock.json` and `requirements.txt` — so they resolved to zero
 * dependencies and the scan reported nothing. Not "could not parse this
 * lockfile": nothing, which reads exactly like a clean result. A pnpm
 * repository (this one included) got a dependency scan that never asked OSV a
 * single question.
 *
 * So every entry in `LOCKFILES` now names the function that parses it. Adding
 * a filename without a parser is a type error rather than a silent hole.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanFinding, Severity } from '../types';

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
}

export interface LockedDependency {
  name: string;
  version: string;
}

type LockfileParser = (content: string) => LockedDependency[];

interface LockfileSupport {
  file: string;
  ecosystem: string;
  parse: LockfileParser;
}

/** Cap per lockfile, so a first run on a neglected tree summarises rather than floods OSV. */
const MAX_DEPS_PER_LOCKFILE = 50;

export async function scanDependencies(targetPath: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];

  for (const { file, ecosystem, parse } of LOCKFILES) {
    const lockPath = join(targetPath, file);
    if (!existsSync(lockPath)) continue;

    let deps: LockedDependency[];
    try {
      deps = dedupe(parse(readFileSync(lockPath, 'utf-8')));
    } catch {
      continue;
    }

    // A lockfile that parsed to nothing is a parser problem, not an empty
    // project — real lockfiles have entries. Say so rather than moving on,
    // because the alternative is a scan that reports clean without asking.
    if (deps.length === 0) {
      findings.push(incompleteFinding(file, 'No dependencies could be read from this lockfile.'));
      continue;
    }

    if (deps.length > MAX_DEPS_PER_LOCKFILE) {
      findings.push(
        incompleteFinding(
          file,
          `Only the first ${MAX_DEPS_PER_LOCKFILE} of ${deps.length} locked packages were checked against OSV.`,
        ),
      );
    }

    for (const dep of deps.slice(0, MAX_DEPS_PER_LOCKFILE)) {
      let vulns: OsvVulnerability[];
      try {
        vulns = await queryOsv(dep.name, dep.version, ecosystem);
      } catch {
        continue;
      }

      for (const vuln of vulns) {
        const cvss = vuln.severity?.find((entry) => entry.type === 'CVSS_V3')?.score;
        findings.push({
          ruleId: 'dependency-known-vulnerability',
          title: 'Dependency CVE',
          file,
          line: 1,
          severity: severityFromCvss(cvss),
          confidence: 'evidence',
          message: `${dep.name}@${dep.version}: ${vuln.summary ?? vuln.id}`,
          consequence: 'A published advisory exists for the exact version resolved in this lockfile.',
          excerpt: `${vuln.id}${cvss ? ` (CVSS: ${cvss})` : ''}`,
          category: 'dependency',
        });
      }
    }
  }

  return findings;
}

/**
 * Coverage the operator did not get. Low severity because nothing dangerous
 * has been found; the point is that the absence of findings for this file
 * carries no information, and a clean report should not imply otherwise.
 */
function incompleteFinding(file: string, message: string): ScanFinding {
  return {
    ruleId: 'dependency-scan-incomplete',
    title: 'Dependency scan incomplete',
    file,
    line: 1,
    severity: 'low',
    confidence: 'evidence',
    message,
    consequence: 'Advisories affecting the unchecked packages would not appear in this report.',
    excerpt: file,
    category: 'dependency',
  };
}

function severityFromCvss(score: string | undefined): Severity {
  if (!score) return 'medium';
  const value = Number.parseFloat(score);
  if (Number.isNaN(value)) return 'medium';
  if (value >= 9) return 'critical';
  if (value >= 7) return 'high';
  if (value >= 4) return 'medium';
  return 'low';
}

/**
 * One query per distinct name@version. Lockfiles repeat a package once per
 * dependent, and a 900-line `yarn.lock` can resolve to a few hundred unique
 * packages — the duplicates would spend the per-file cap on questions already
 * asked.
 */
function dedupe(deps: LockedDependency[]): LockedDependency[] {
  const seen = new Set<string>();
  const unique: LockedDependency[] = [];
  for (const dep of deps) {
    const key = `${dep.name}@${dep.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(dep);
  }
  return unique;
}

/**
 * Split `name@version` where the name may itself begin with `@`.
 *
 * `@babel/core@7.24.7` has two `@`, and only the last one separates. Anything
 * without a separating `@` is a spec this parser does not understand, and is
 * dropped rather than guessed at.
 */
function splitNameVersion(spec: string): LockedDependency | null {
  const at = spec.lastIndexOf('@');
  if (at <= 0) return null;
  const name = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (!name || !version) return null;
  return { name, version };
}

/**
 * A resolved version, or null if the string is a range, a tag or a URL.
 *
 * OSV answers questions about exact versions. `^7.0.0`, `next` and
 * `github:owner/repo` are not versions, and sending them produces a confident
 * empty answer — the worst possible result, because it looks like "no known
 * advisories".
 */
function exactVersion(raw: string): string | null {
  const version = raw.trim().replace(/^[=v]+/, '');
  return /^[0-9][0-9a-zA-Z.+-]*$/.test(version) ? version : null;
}

function parsePackageLock(content: string): LockedDependency[] {
  const lock = JSON.parse(content) as {
    packages?: Record<string, { version?: string }>;
    dependencies?: Record<string, { version?: string }>;
  };
  const packages = lock.packages ?? lock.dependencies ?? {};
  const deps: LockedDependency[] = [];
  for (const [key, value] of Object.entries(packages)) {
    // v2+ keys are paths (`node_modules/a/node_modules/b`); the package is the
    // last segment, not the whole path.
    const name = key.replace(/^.*node_modules\//, '');
    const version = value?.version;
    if (name && version && !name.startsWith('.')) deps.push({ name, version });
  }
  return deps;
}

/**
 * pnpm writes its resolved tree as keys under `packages:`, and has changed the
 * shape of those keys three times:
 *
 *   v5   `/@babel/core/7.24.7:`
 *   v6   `/@babel/core@7.24.7:`
 *   v9   `'@babel/core@7.24.7':`
 *
 * All three are handled by normalising the key rather than by detecting the
 * lockfile version, because a scanner that recognises only the version it was
 * written against fails silently on the next one — which is the failure this
 * file exists to fix.
 *
 * Peer-dependency suffixes (`(react@18.3.1)`, `_react@17.0.2`) are stripped:
 * they describe the resolution context, not the package.
 */
function parsePnpmLock(content: string): LockedDependency[] {
  const deps: LockedDependency[] = [];
  let inPackages = false;

  for (const line of content.split('\n')) {
    if (/^[a-zA-Z]/.test(line)) {
      inPackages = line.startsWith('packages:');
      continue;
    }
    if (!inPackages) continue;

    // Entries sit exactly one level in. Deeper lines are the entry's fields.
    const match = /^ {2}(?! )(.+):\s*$/.exec(line);
    if (!match?.[1]) continue;

    let key = match[1].trim().replace(/^['"]|['"]$/g, '');
    key = key.replace(/^\//, '');
    // Parentheses cannot occur in a package name, so the v6/v9 peer suffix can
    // be cut from the whole key.
    key = key.replace(/\(.*$/, '');

    // v5 separated the version with a slash. It is split here rather than
    // rewritten into the `@` form, because a v5 peer suffix (`_react@17.0.2`)
    // contains an `@` of its own and would capture the generic splitter.
    let name: string;
    let rawVersion: string;
    const slashed = /^(@?[^@]+)\/([0-9][^/]*)$/.exec(key);
    if (slashed?.[1] && slashed[2]) {
      name = slashed[1];
      rawVersion = slashed[2];
    } else {
      const dep = splitNameVersion(key);
      if (!dep) continue;
      name = dep.name;
      rawVersion = dep.version;
    }

    // The v5 peer suffix is an underscore, which *is* legal in a package name
    // — so it is only ever stripped from the version, never from the name.
    const version = exactVersion(rawVersion.replace(/_.*$/, ''));
    if (version) deps.push({ name, version });
  }

  return deps;
}

/**
 * Both yarn dialects, which differ in punctuation rather than structure:
 *
 *   v1      `"@babel/core@^7.0.0":` then `  version "7.24.7"`
 *   berry   `"@babel/core@npm:^7.0.0":` then `  version: 7.24.7`
 *
 * The header carries the name and the indented `version` carries the truth, so
 * the parser holds the last header and waits.
 */
function parseYarnLock(content: string): LockedDependency[] {
  const deps: LockedDependency[] = [];
  let pendingName: string | null = null;

  for (const line of content.split('\n')) {
    if (line.startsWith('#') || line.trim() === '') continue;

    if (!/^\s/.test(line)) {
      pendingName = null;
      const header = line.replace(/:\s*$/, '');
      // Multiple specs share one entry; they name the same package, so the
      // first is enough.
      const first = header.split(',')[0]?.trim().replace(/^['"]|['"]$/g, '');
      if (!first) continue;
      // `__metadata:` and other berry bookkeeping blocks are not packages.
      if (!first.includes('@') || first === '__metadata') continue;
      // Anything resolved by a non-registry protocol is local to this
      // checkout — the workspace root resolves to `0.0.0-use.local`, which is
      // a well-formed version of a package no registry has ever heard of.
      // Asking OSV about it spends the per-file cap on a guaranteed miss.
      if (/@(?:workspace|file|link|portal|exec|patch):/.test(first)) continue;
      const dep = splitNameVersion(first.replace(/@npm:/, '@'));
      if (dep) pendingName = dep.name;
      continue;
    }

    if (!pendingName) continue;
    const version = /^\s+version:?\s+["']?([^"'\s]+)["']?\s*$/.exec(line);
    if (!version?.[1]) continue;
    const exact = exactVersion(version[1]);
    if (exact) deps.push({ name: pendingName, version: exact });
    pendingName = null;
  }

  return deps;
}

/** Pipenv's lockfile is JSON, with versions written as the `==x.y.z` specifier. */
function parsePipfileLock(content: string): LockedDependency[] {
  const lock = JSON.parse(content) as Record<string, Record<string, { version?: string }>>;
  const deps: LockedDependency[] = [];

  for (const section of ['default', 'develop']) {
    const packages = lock[section];
    if (!packages || typeof packages !== 'object') continue;
    for (const [name, value] of Object.entries(packages)) {
      // VCS and file entries carry a ref instead of a version. There is no
      // version to ask OSV about, so they are skipped.
      const version = exactVersion(String(value?.version ?? '').replace(/^==/, ''));
      if (name && version) deps.push({ name, version });
    }
  }

  return deps;
}

/**
 * Only `==` pins are usable. A range gives OSV nothing to answer against, and
 * the previous `([0-9.]+)` version pattern also silently dropped every
 * pre-release and post-release pin PEP 440 allows (`2.0.0rc1`, `1.4.post1`),
 * which are ordinary in pinned production requirements.
 */
function parseRequirementsTxt(content: string): LockedDependency[] {
  const deps: LockedDependency[] = [];

  for (const raw of content.split('\n')) {
    // Environment markers and comments both describe the pin rather than
    // being part of it.
    const line = raw.split('#')[0]?.split(';')[0]?.trim();
    if (!line || line.startsWith('-')) continue;

    const match = /^([a-zA-Z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s,]+)/.exec(line);
    if (!match?.[1] || !match[2]) continue;
    // A wildcard pin (`==1.4.*`) is a range wearing an equals sign.
    const version = exactVersion(match[2]);
    if (version) deps.push({ name: match[1], version });
  }

  return deps;
}

const LOCKFILES: readonly LockfileSupport[] = [
  { file: 'package-lock.json', ecosystem: 'npm', parse: parsePackageLock },
  { file: 'pnpm-lock.yaml', ecosystem: 'npm', parse: parsePnpmLock },
  { file: 'yarn.lock', ecosystem: 'npm', parse: parseYarnLock },
  { file: 'requirements.txt', ecosystem: 'PyPI', parse: parseRequirementsTxt },
  { file: 'Pipfile.lock', ecosystem: 'PyPI', parse: parsePipfileLock },
];

/** Exposed so the parsers can be tested without a network or a fixture tree. */
export const LOCKFILE_PARSERS: Readonly<Record<string, LockfileParser>> = Object.fromEntries(
  LOCKFILES.map((entry) => [entry.file, entry.parse]),
);

/** Package names and versions are validated before they reach the query body. */
function isValidPackageName(name: string): boolean {
  return /^[@a-zA-Z0-9_.\-/]{1,214}$/.test(name);
}

function isValidVersion(version: string): boolean {
  return /^[0-9a-zA-Z._\-+]{1,50}$/.test(version);
}

async function queryOsv(name: string, version: string, ecosystem: string): Promise<OsvVulnerability[]> {
  if (!isValidPackageName(name) || !isValidVersion(version)) return [];

  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem }, version }),
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return [];
    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    return data.vulns ?? [];
  } catch {
    return [];
  }
}
