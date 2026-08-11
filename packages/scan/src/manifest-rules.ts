/**
 * Dependency-manifest rules — typosquats, dependency confusion, and
 * install-time lifecycle scripts.
 *
 * This is the one detector here that does not need a vulnerability to exist
 * yet. `event-stream` (2018), `ua-parser-js` (2021) and `node-ipc` (2022) were
 * all advisory-clean at the moment they were installed; the advisory gets
 * written *after* somebody notices. What they shared was a name you would
 * misread and a lifecycle script that ran with the installing user's
 * privileges. Both are visible in the manifest, before anything is fetched.
 */

import type { Severity } from './types';

export interface ManifestFinding {
  ruleId: string;
  title: string;
  line: number;
  severity: Severity;
  cwe: string;
  message: string;
  consequence: string;
  excerpt: string;
}

/**
 * Popular package names, by ecosystem.
 *
 * Not a registry mirror and not trying to be. It is the set of names worth
 * *impersonating* — a typosquat only pays off against a package people install
 * without looking. A longer list would not find more attacks; it would find
 * more legitimate packages that happen to sit one edit from something famous.
 */
const POPULAR_NPM = [
  'react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'debug',
  'moment', 'dayjs', 'uuid', 'dotenv', 'typescript', 'webpack', 'vite', 'rollup',
  'eslint', 'prettier', 'jest', 'vitest', 'mocha', 'chai', 'sinon', 'request',
  'node-fetch', 'cross-env', 'rimraf', 'glob', 'minimist', 'yargs', 'inquirer',
  'colors', 'ora', 'semver', 'ws', 'socket.io', 'mongoose', 'sequelize', 'knex',
  'pg', 'mysql', 'mysql2', 'redis', 'ioredis', 'jsonwebtoken', 'bcrypt', 'passport',
  'cors', 'helmet', 'morgan', 'body-parser', 'multer', 'nodemailer', 'puppeteer',
  'playwright', 'cheerio', 'sharp', 'canvas', 'esbuild', 'babel', 'postcss',
  'tailwindcss', 'next', 'nuxt', 'vue', 'svelte', 'angular', 'rxjs', 'zod',
];

const POPULAR_PYPI = [
  'requests', 'urllib3', 'numpy', 'pandas', 'scipy', 'flask', 'django', 'fastapi',
  'sqlalchemy', 'pydantic', 'click', 'jinja2', 'pyyaml', 'boto3', 'botocore',
  'setuptools', 'wheel', 'pip', 'six', 'certifi', 'idna', 'chardet', 'attrs',
  'python-dateutil', 'pytz', 'pytest', 'tox', 'black', 'flake8', 'mypy', 'isort',
  'beautifulsoup4', 'lxml', 'pillow', 'matplotlib', 'seaborn', 'scikit-learn',
  'tensorflow', 'torch', 'transformers', 'openai', 'anthropic', 'httpx', 'aiohttp',
  'celery', 'redis', 'psycopg2', 'pymongo', 'cryptography', 'paramiko', 'colorama',
];

/**
 * Names that read as belonging to a private registry.
 *
 * A manifest that asks a public index for a package whose name announces it is
 * internal is the dependency-confusion setup: whoever registers the name
 * publicly first wins, and the build takes their copy.
 */
const INTERNAL_MARKER = /(?:^|[-_/@])(?:internal|private|corp|intranet|inhouse|confidential)(?:$|[-_/])/i;

/** Strip the separators a squatter varies but a reader does not notice. */
function normalizeName(name: string): string {
  return name.toLowerCase().replace(/^@/, '').replace(/[-_.\s]/g, '');
}

/**
 * Damerau-Levenshtein distance, capped.
 *
 * Damerau rather than plain Levenshtein because the single most common
 * typosquat is a transposition — `lodahs` for `lodash`, `reqeust` for
 * `request`. Levenshtein scores those as 2, the same as two unrelated edits,
 * which puts them below any threshold tight enough to be useful.
 */
export function editDistance(a: string, b: string, cap = 3): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > cap) return cap + 1;

  const rows: number[][] = [];
  for (let i = 0; i <= a.length; i += 1) {
    rows.push(new Array<number>(b.length + 1).fill(0));
    rows[i]![0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) rows[0]![j] = j;

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let best = Math.min(
        rows[i - 1]![j]! + 1,
        rows[i]![j - 1]! + 1,
        rows[i - 1]![j - 1]! + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, rows[i - 2]![j - 2]! + 1);
      }
      rows[i]![j] = best;
    }
  }
  return rows[a.length]![b.length]!;
}

export interface SquatVerdict {
  impersonates: string;
  /** `separator` when only punctuation differs, `edit` when a character does. */
  kind: 'separator' | 'edit';
}

/**
 * Whether `name` looks like an attempt to be mistaken for a popular package.
 *
 * Exact matches return null first, always. The check that follows is
 * deliberately asymmetric: a name is suspicious for being *close to* a popular
 * package, never for being popular itself.
 */
export function detectTyposquat(name: string, ecosystem: 'npm' | 'pypi'): SquatVerdict | null {
  const popular = ecosystem === 'npm' ? POPULAR_NPM : POPULAR_PYPI;
  const lower = name.toLowerCase();

  // A scoped name is left alone, scope and all.
  //
  // Discarding the scope before comparing was this rule's largest source of
  // false positives, and it fired on some of the most widely installed packages
  // there are: `@babel/core`, `@angular/core`, `@nestjs/core` and
  // `@capacitor/core` all reduce to `core`, which sits one edit from `cors`.
  //
  // Scopes are owned. Publishing `@babel/anything` requires control of the
  // `@babel` scope, so a squat cannot be planted inside a legitimate one, and
  // nobody typing `npm i cors` arrives at `@capacitor/core` by accident. The
  // misreading this rule exists to catch does not cross the scope boundary, so
  // a name that has one is not a candidate.
  //
  // The scoped attack that *is* real is a lookalike scope — `@babeljs/core` for
  // `@babel/core`. Catching it means comparing scopes against a list of popular
  // scopes, which is a different check than this one rather than a variation on
  // it. Stripping the scope never performed that check; it only compared the
  // part after the slash, so nothing is lost here.
  if (/^@[^/]+\//.test(lower)) return null;

  if (popular.includes(lower)) return null;
  if (lower.length < 4) return null;

  const normalized = normalizeName(lower);
  for (const candidate of popular) {
    const candidateNormalized = normalizeName(candidate);
    // `urllib-3` and `pythondateutil` normalise onto their targets exactly.
    // Nothing legitimate reaches a popular package's spelling by deleting or
    // inserting punctuation.
    if (normalized === candidateNormalized) return { impersonates: candidate, kind: 'separator' };
    if (editDistance(normalized, candidateNormalized, 1) === 1) {
      return { impersonates: candidate, kind: 'edit' };
    }
  }
  return null;
}

const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

/**
 * Scan a `package.json`.
 *
 * Text-oriented rather than object-oriented so every finding can carry the
 * line it came from. A finding an operator cannot navigate to is a finding
 * they will not act on.
 */
export function scanPackageJson(text: string): ManifestFinding[] {
  const findings: ManifestFinding[] = [];
  const lines = text.split('\n');

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return findings;
  }

  const lineOf = (needle: string): number => {
    const index = lines.findIndex((line) => line.includes(`"${needle}"`));
    return index === -1 ? 1 : index + 1;
  };

  const depBuckets = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const bucket of depBuckets) {
    const deps = parsed[bucket];
    if (!deps || typeof deps !== 'object') continue;
    for (const name of Object.keys(deps as Record<string, unknown>)) {
      const line = lineOf(name);

      if (INTERNAL_MARKER.test(name)) {
        findings.push({
          ruleId: 'manifest-dependency-confusion',
          title: 'internal-looking package resolved from a public registry',
          line,
          severity: 'critical',
          cwe: 'CWE-1357',
          message: `"${name}" names itself as internal but carries no registry pin`,
          consequence:
            'Whoever registers this name publicly first wins the resolution, and their code runs in your build.',
          excerpt: (lines[line - 1] ?? '').trim(),
        });
        continue;
      }

      const squat = detectTyposquat(name, 'npm');
      if (squat) {
        findings.push({
          ruleId: 'manifest-typosquat',
          title: 'dependency name close to a popular package',
          line,
          severity: 'high',
          cwe: 'CWE-1357',
          message:
            squat.kind === 'separator'
              ? `"${name}" differs from "${squat.impersonates}" only in punctuation`
              : `"${name}" is one edit from "${squat.impersonates}"`,
          consequence:
            'A reviewer scanning a diff reads the name they expected. The package that installs is the one that was written.',
          excerpt: (lines[line - 1] ?? '').trim(),
        });
      }
    }
  }

  const scripts = parsed.scripts;
  if (scripts && typeof scripts === 'object') {
    for (const [name, body] of Object.entries(scripts as Record<string, unknown>)) {
      if (!LIFECYCLE_SCRIPTS.includes(name)) continue;
      findings.push({
        ruleId: 'manifest-install-lifecycle-script',
        title: 'install-time lifecycle script',
        line: lineOf(name),
        severity: 'medium',
        cwe: 'CWE-506',
        message: `"${name}" runs automatically on install: ${String(body).slice(0, 120)}`,
        consequence:
          'Lifecycle scripts run with the installing user’s privileges and network access, before any code is reviewed. It is the execution vector every notable npm compromise has used.',
        excerpt: (lines[lineOf(name) - 1] ?? '').trim(),
      });
    }
  }

  return findings;
}

/** Scan a `requirements.txt`. Same checks, different grammar. */
export function scanRequirementsTxt(text: string): ManifestFinding[] {
  const findings: ManifestFinding[] = [];
  const lines = text.split('\n');

  lines.forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) return;

    const match = /^([A-Za-z0-9_.-]+)\s*(?:[=<>!~]=|@|$)/.exec(line);
    const name = match?.[1];
    if (!name) return;

    if (INTERNAL_MARKER.test(name)) {
      findings.push({
        ruleId: 'manifest-dependency-confusion',
        title: 'internal-looking package resolved from a public index',
        line: index + 1,
        severity: 'critical',
        cwe: 'CWE-1357',
        message: `"${name}" names itself as internal but carries no index pin`,
        consequence:
          'pip resolves the highest version across every configured index, so a public package of the same name shadows the private one.',
        excerpt: line,
      });
      return;
    }

    const squat = detectTyposquat(name, 'pypi');
    if (squat) {
      findings.push({
        ruleId: 'manifest-typosquat',
        title: 'dependency name close to a popular package',
        line: index + 1,
        severity: 'high',
        cwe: 'CWE-1357',
        message:
          squat.kind === 'separator'
            ? `"${name}" differs from "${squat.impersonates}" only in punctuation`
            : `"${name}" is one edit from "${squat.impersonates}"`,
        consequence:
          'A reviewer scanning a diff reads the name they expected. The package that installs is the one that was written.',
        excerpt: line,
      });
    }
  });

  return findings;
}
