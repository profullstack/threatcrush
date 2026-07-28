/**
 * Source scanning — the `sast` subsystem of `code-scanner`.
 *
 * Implements PRD 0004. See `rules.ts` for the design constraint that shapes
 * everything here: findings carry a confidence, and a bare pattern match can
 * never present as high severity.
 *
 * This subsystem is deliberately narrow and says so. CodeQL and Semgrep run in
 * this repo's CI and do real interprocedural analysis; the value added here is
 * coverage of source that never reached the repository — vendored trees,
 * generated files, a hotfix applied in place on the box.
 */

export * from './rules.js';

import { open, readdir } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { extname, join } from 'node:path';

import { scanSource, type SastFinding, type SuppressionRecord } from './rules.js';

export interface SastFileFinding extends SastFinding {
  file: string;
  /** Third-party or generated code: ranked down, never hidden. */
  vendored: boolean;
}

export interface SastOptions {
  paths: readonly string[];
  maxDepth: number;
  maxFileBytes: number;
  /** `rank_down` demotes vendored findings; `equal` leaves them. */
  vendored: 'rank_down' | 'equal';
  minConfidence: 'pattern' | 'contextual';
}

export interface SastResult {
  findings: SastFileFinding[];
  filesScanned: number;
  suppressions: (SuppressionRecord & { file: string })[];
}

export const SAST_DEFAULTS: SastOptions = {
  paths: ['/srv', '/var/www', '/opt'],
  maxDepth: 8,
  maxFileBytes: 2_000_000,
  vendored: 'rank_down',
  minConfidence: 'pattern',
};

const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  '.turbo',
  '.cache',
  'coverage',
  '__pycache__',
  '.venv',
]);

/**
 * Paths whose findings are ranked down.
 *
 * A vulnerability in vendored code still executes; it is simply less likely to
 * be the operator's to fix, and `deps/` already covers third-party packages by
 * version. Minified bundles are included because a finding in a 40,000-column
 * line is unactionable regardless of whether it is real.
 */
const VENDORED = /(?:^|\/)(?:vendor|third_party|thirdparty|bundled|generated|dist|build|public\/assets)(?:\/|$)|\.min\.js$|\.bundle\.js$/;

export function isVendored(path: string): boolean {
  return VENDORED.test(path);
}

const CONFIDENCE_RANK = { pattern: 0, contextual: 1 };
const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

/** One step down the ladder, floored at low. */
function demote(severity: SastFinding['severity']): SastFinding['severity'] {
  const order: SastFinding['severity'][] = ['low', 'medium', 'high', 'critical'];
  return order[Math.max(0, order.indexOf(severity) - 1)]!;
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
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
      out.push(path);
    }
  }
}

/**
 * Scan configured paths for dangerous constructs.
 *
 * Options in, result out, no `ModuleContext` — matching `deps` and `secrets`,
 * so the same entry point serves the daemon and the one-shot CLI.
 */
export async function scanSast(options: SastOptions): Promise<SastResult> {
  const findings: SastFileFinding[] = [];
  const suppressions: (SuppressionRecord & { file: string })[] = [];
  let filesScanned = 0;

  for (const base of options.paths) {
    const files: string[] = [];
    await walk(base, 0, options.maxDepth, files);

    for (const file of files) {
      // One file handle for the size check and the read, matching `secrets/`.
      // `stat(path)` then `readFile(path)` is a time-of-check/time-of-use gap:
      // the path can be swapped between the calls, so the bytes analysed need
      // not be the bytes measured. Holding a descriptor and stat-ing that
      // removes the gap.
      let text: string;
      let handle: FileHandle | undefined;
      try {
        handle = await open(file, 'r');
        if ((await handle.stat()).size > options.maxFileBytes) continue;
        text = await handle.readFile('utf8');
      } catch {
        continue;
      } finally {
        await handle?.close().catch(() => {
          /* a failed close must not abort the scan */
        });
      }

      filesScanned += 1;
      const vendored = isVendored(file);
      const result = scanSource(text);

      for (const record of result.suppressions) suppressions.push({ ...record, file });

      for (const finding of result.findings) {
        if (CONFIDENCE_RANK[finding.confidence] < CONFIDENCE_RANK[options.minConfidence]) continue;
        findings.push({
          ...finding,
          file,
          vendored,
          severity:
            vendored && options.vendored === 'rank_down' ? demote(finding.severity) : finding.severity,
        });
      }
    }
  }

  findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file),
  );

  return { findings, filesScanned, suppressions };
}
