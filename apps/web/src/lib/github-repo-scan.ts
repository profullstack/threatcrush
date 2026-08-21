import {
  SCAN_EXTENSIONS,
  SKIP_DIRS,
  languageOf,
  peakSeverity,
  scanManifest,
  scanText,
  type ScanFinding,
} from "@threatcrush/scan";
import {
  fetchBlobText,
  listTree,
  type FetchLike,
  type TreeEntry,
} from "@/lib/github-app";

/**
 * Scan one repository through the GitHub API.
 *
 * There is no filesystem here and no clone. The tree API gives every path in
 * one request, and blobs are fetched individually for the files worth reading.
 * That trades bandwidth for API calls, which is the right way round: a clone of
 * a large monorepo would blow both the memory and the time budget of a web
 * process, while blob fetches are bounded and can be capped mid-flight.
 *
 * The caps below are the whole safety story. An installation can point this at
 * an arbitrarily large repository, so every dimension that could grow without
 * bound — files read, bytes per file, findings kept — has a ceiling, and the
 * result says plainly when a ceiling was hit. A truncated scan reported as a
 * clean one would be worse than no scan at all.
 */

/** Files read per repository. */
export const MAX_FILES = 400;
/** Per-file ceiling. Rules run per line; a minified bundle is all cost, no signal. */
export const MAX_FILE_BYTES = 256 * 1024;
/** Findings retained. Beyond this the list stops being triage and starts being noise. */
export const MAX_FINDINGS = 500;
/** Blob fetches in flight. Courtesy to GitHub's secondary rate limits. */
export const CONCURRENCY = 8;

const MANIFESTS = new Set(["package.json", "requirements.txt"]);

/**
 * Lockfiles and vendored trees are other people's code. Scanning them produces
 * findings the installer cannot act on, which is the fastest way to make a
 * security tool ignorable.
 */
const SKIP_FILES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "composer.lock",
  "Cargo.lock",
  "poetry.lock",
  "go.sum",
]);

export function isSkippedPath(path: string): boolean {
  const segments = path.split("/");
  const basename = segments[segments.length - 1];

  if (SKIP_FILES.has(basename)) return true;
  if (segments.some((segment) => (SKIP_DIRS as ReadonlySet<string>).has(segment))) return true;
  // A minified or bundled artifact is generated, not authored.
  if (/\.min\.(js|css)$/.test(basename)) return true;
  if (/\.(map|lock)$/.test(basename)) return true;

  return false;
}

export function isScannable(entry: TreeEntry): boolean {
  if (isSkippedPath(entry.path)) return false;
  if (entry.size > MAX_FILE_BYTES) return false;
  // A zero-byte file has nothing to match and still costs a request.
  if (entry.size === 0) return false;

  const basename = entry.path.split("/").pop() || "";
  if (MANIFESTS.has(basename)) return true;

  const dot = basename.lastIndexOf(".");
  if (dot <= 0) return false;
  const ext = basename.slice(dot);
  return (SCAN_EXTENSIONS as ReadonlySet<string>).has(ext);
}

/**
 * Rank the files so that, when the cap bites, what got read is the part of the
 * repository most likely to matter. Manifests first (dependency risk applies to
 * the whole tree), then everything else shallowest-first, since a file at the
 * root is more often the application and less often a fixture.
 */
export function prioritise(entries: TreeEntry[]): TreeEntry[] {
  return [...entries].sort((a, b) => {
    const aManifest = MANIFESTS.has(a.path.split("/").pop() || "") ? 0 : 1;
    const bManifest = MANIFESTS.has(b.path.split("/").pop() || "") ? 0 : 1;
    if (aManifest !== bManifest) return aManifest - bManifest;

    const aDepth = a.path.split("/").length;
    const bDepth = b.path.split("/").length;
    if (aDepth !== bDepth) return aDepth - bDepth;

    return a.path.localeCompare(b.path);
  });
}

export type RepoScanResult = {
  ref: string;
  filesConsidered: number;
  filesScanned: number;
  findings: ScanFinding[];
  /** True when the file cap or GitHub's own tree truncation cut the scan short. */
  truncated: boolean;
  truncationReason: string | null;
  peak: string | null;
};

/**
 * Run `n` tasks with a bounded number in flight. A plain `Promise.all` over 400
 * blob fetches would open 400 sockets and trip GitHub's secondary rate limit,
 * which is answered with a 403 and a cooldown rather than a retry header.
 */
async function mapLimit<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;

  async function run(): Promise<void> {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return results;
}

export async function scanRepository(
  installationToken: string,
  fullName: string,
  ref: string,
  fetchImpl: FetchLike = fetch
): Promise<RepoScanResult> {
  const { entries, truncated: treeTruncated } = await listTree(
    installationToken,
    fullName,
    ref,
    fetchImpl
  );

  const scannable = prioritise(entries.filter(isScannable));
  const selected = scannable.slice(0, MAX_FILES);

  const perFile = await mapLimit(selected, CONCURRENCY, async (entry) => {
    const text = await fetchBlobText(installationToken, fullName, entry.sha, fetchImpl);
    if (text === null) return null;

    const basename = entry.path.split("/").pop() || "";
    // A manifest needs both passes. `scanManifest` only ever returns dependency
    // findings — it does not run the text rules — so running it alone on a
    // package.json would miss a token committed into that same file.
    const findings = scanText(entry.path, text, languageOf(entry.path));
    if (MANIFESTS.has(basename)) {
      findings.push(...scanManifest(entry.path, basename, text));
    }

    return { path: entry.path, findings };
  });

  const findings: ScanFinding[] = [];
  let filesScanned = 0;
  for (const result of perFile) {
    if (!result) continue;
    filesScanned++;
    findings.push(...result.findings);
  }

  const overflowed = findings.length > MAX_FINDINGS;
  const kept = overflowed ? findings.slice(0, MAX_FINDINGS) : findings;

  const cappedFiles = scannable.length > MAX_FILES;
  const truncated = treeTruncated || cappedFiles || overflowed;
  const truncationReason = treeTruncated
    ? "GitHub truncated the repository tree"
    : cappedFiles
      ? `Only the first ${MAX_FILES} of ${scannable.length} scannable files were read`
      : overflowed
        ? `Only the first ${MAX_FINDINGS} of ${findings.length} findings were kept`
        : null;

  return {
    ref,
    filesConsidered: scannable.length,
    filesScanned,
    findings: kept,
    truncated,
    truncationReason,
    peak: peakSeverity(kept),
  };
}
