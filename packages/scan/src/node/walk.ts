/**
 * The filesystem half of the scan engine: walk a tree, read what is scannable,
 * hand the text to the rules.
 *
 * Split from `../text.ts` because this file imports `node:fs` and that one must
 * not. The package's default entry point is consumed by browser bundles, and a
 * single filesystem import anywhere in its graph breaks all of them. Everything
 * that needs a disk lives behind the `./node` entry point instead.
 */

import {
  closeSync, fstatSync, openSync, readdirSync, readFileSync, readSync, statSync,
} from 'node:fs';
import { basename, dirname, extname, join, relative, sep } from 'node:path';
import { SENSITIVE_FILES } from '../secret-rules.js';
import {
  collectSuppressions,
  languageOf,
  languageOfShebang,
  SCAN_EXTENSIONS,
  scanManifest,
  scanText,
  SKIP_DIRS,
} from '../text.js';
import type { ScanFinding, ScanLanguage } from '../types.js';
import { severityRank } from '../types.js';

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
