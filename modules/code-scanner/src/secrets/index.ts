/**
 * Secret scanning — the `secrets` subsystem of `code-scanner`.
 *
 * Implements PRD 0003. The scope that distinguishes this from `gitleaks` in CI
 * is the filesystem: this runs on the box, so it sees the things that never
 * passed through a commit — a hand-written `.env`, a `config.json.bak` in a web
 * root, credentials baked into a gitignored `dist/`, an exposed `.git`.
 *
 * Two defaults here are deliberate inversions of what a repository scanner
 * would do:
 *
 *  - **Gitignored files are scanned, not skipped.** They are simultaneously the
 *    likeliest place for a real credential and the least likely to have been
 *    looked at, precisely because every repo-oriented tool ignores them.
 *  - **High-risk filenames are scanned even when the size or type rules would
 *    otherwise skip them.** A 6 MB `.env` is still a `.env`.
 */

export * from './rules.js';

import { readdir, readFile, stat } from 'node:fs/promises';
import { basename, extname, join, relative } from 'node:path';

import { scanText, type SecretMatch } from './rules.js';

export interface SecretFinding extends SecretMatch {
  file: string;
  /** True when the file is excluded from version control. */
  gitignored: boolean;
}

export interface SecretsOptions {
  paths: readonly string[];
  maxDepth: number;
  maxFileBytes: number;
  entropyEnabled: boolean;
  scanGitignored: boolean;
  /** Fingerprints and path globs a human has reviewed and dismissed. */
  allow: readonly string[];
}

export interface SecretsResult {
  findings: SecretFinding[];
  filesScanned: number;
  /** Files that could not be read or were too large — never silently dropped. */
  skipped: { file: string; reason: string }[];
}

export const SECRETS_DEFAULTS: SecretsOptions = {
  paths: ['/srv', '/var/www', '/opt'],
  maxDepth: 8,
  maxFileBytes: 5_000_000,
  entropyEnabled: true,
  scanGitignored: true,
  allow: [],
};

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'vendor',
  '.next',
  '.turbo',
  '.cache',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
]);

/** Binary and media extensions that cannot hold a readable credential. */
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.bmp', '.tiff',
  '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm', '.ogg', '.flac',
  '.zip', '.gz', '.tar', '.bz2', '.xz', '.7z', '.rar',
  '.pdf', '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.so', '.dylib', '.dll', '.exe', '.bin', '.wasm', '.class', '.pyc',
  '.glb', '.gltf', '.fbx', '.blend',
]);

/**
 * Filenames that are scanned regardless of the other rules.
 *
 * These are where credentials actually live, and several of them are extensions
 * the skip list would otherwise reject.
 */
const HIGH_RISK = [
  /^\.env(\..*)?$/i,
  /^\.npmrc$/i,
  /^\.pgpass$/i,
  /^\.netrc$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)$/i,
  /^credentials$/i,
  /^config\.json$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.kdbx$/i,
  /\.ovpn$/i,
];

export function isHighRisk(name: string): boolean {
  return HIGH_RISK.some((pattern) => pattern.test(name));
}

/** Does the buffer look like binary content? */
export function looksBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 8000);
  // A NUL byte is the classic signal and is decisive.
  if (sample.includes(0)) return true;

  let control = 0;
  for (const byte of sample) {
    if (byte < 7 || (byte > 14 && byte < 32)) control += 1;
  }
  return sample.length > 0 && control / sample.length > 0.3;
}

/**
 * Read a repository's ignore patterns.
 *
 * Only used to *label* findings (PRD 0003 R4), never to skip them: a gitignored
 * file is more interesting, not less. Full gitignore semantics are not
 * implemented — a suffix/segment match is enough to annotate a finding, and
 * over-labelling costs nothing.
 */
export async function readGitignore(root: string): Promise<string[]> {
  try {
    const text = await readFile(join(root, '.gitignore'), 'utf8');
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'))
      .map((line) => line.replace(/^\/+|\/+$/g, ''));
  } catch {
    return [];
  }
}

export function matchesIgnore(relativePath: string, patterns: readonly string[]): boolean {
  const segments = relativePath.split('/');
  return patterns.some((pattern) => {
    if (pattern.includes('*')) {
      const suffix = pattern.replace(/^\*+/, '');
      return suffix.length > 1 && relativePath.endsWith(suffix);
    }
    return segments.includes(pattern);
  });
}

/** Is this finding covered by a reviewed allowlist entry? */
export function isAllowed(
  finding: { fingerprint: string; file: string },
  allow: readonly string[],
): boolean {
  return allow.some((entry) => {
    if (entry.startsWith('sha256:')) return finding.fingerprint === entry;
    if (entry.includes('*')) {
      const inner = entry.replace(/^\*+/, '').replace(/\*+$/, '');
      return inner.length > 0 && finding.file.includes(inner);
    }
    // A trailing slash means "everything under this directory", which is what
    // an operator writing `tests/` intends. Without this the entry would only
    // ever match a file literally named `tests/`.
    if (entry.endsWith('/')) return finding.file.includes(`/${entry}`);
    return finding.file === entry || finding.file.endsWith(`/${entry}`);
  });
}

async function walk(dir: string, depth: number, maxDepth: number, out: string[]): Promise<void> {
  if (depth > maxDepth) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      await walk(path, depth + 1, maxDepth, out);
    } else if (entry.isFile()) {
      out.push(path);
    }
  }
}

/**
 * Scan the configured paths for credentials.
 *
 * Takes options and returns a result with no `ModuleContext`, matching the
 * `deps` subsystem, so the same entry point serves the daemon and the one-shot
 * `scan --secrets`.
 */
export async function scanSecrets(options: SecretsOptions): Promise<SecretsResult> {
  const findings: SecretFinding[] = [];
  const skipped: { file: string; reason: string }[] = [];
  let filesScanned = 0;

  for (const base of options.paths) {
    const files: string[] = [];
    await walk(base, 0, options.maxDepth, files);
    const ignorePatterns = await readGitignore(base);

    for (const file of files) {
      const name = basename(file);
      const highRisk = isHighRisk(name);

      if (!highRisk && SKIP_EXTENSIONS.has(extname(file).toLowerCase())) continue;

      let size: number;
      try {
        size = (await stat(file)).size;
      } catch {
        skipped.push({ file, reason: 'unreadable' });
        continue;
      }

      if (size === 0) continue;
      if (size > options.maxFileBytes && !highRisk) {
        // Recorded rather than silently dropped: an unscanned file must never
        // be indistinguishable from a clean one (PRD 0002 R6, PRD 0003 R2).
        skipped.push({ file, reason: `larger than ${options.maxFileBytes} bytes` });
        continue;
      }

      let buffer: Buffer;
      try {
        buffer = await readFile(file);
      } catch {
        skipped.push({ file, reason: 'unreadable' });
        continue;
      }

      if (!highRisk && looksBinary(buffer)) continue;

      filesScanned += 1;
      const relativePath = relative(base, file);
      const gitignored = matchesIgnore(relativePath, ignorePatterns);
      if (gitignored && !options.scanGitignored) continue;

      for (const match of scanText(buffer.toString('utf8'), {
        entropyEnabled: options.entropyEnabled,
      })) {
        const finding: SecretFinding = { ...match, file, gitignored };
        if (isAllowed(finding, options.allow)) continue;
        findings.push(finding);
      }
    }
  }

  const rank = { low: 0, medium: 1, high: 2, critical: 3 };
  findings.sort((a, b) => rank[b.severity] - rank[a.severity] || a.file.localeCompare(b.file));

  return { findings, filesScanned, skipped };
}
