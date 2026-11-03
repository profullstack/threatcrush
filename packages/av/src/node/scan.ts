import { createHash } from 'node:crypto';
import { createReadStream, readFileSync, existsSync } from 'node:fs';
import { applyReputation, DEFAULT_HEURISTIC_BYTES, scanBytes, SignatureSet } from '../engine';
import { lookupHashes } from '../reputation';
import { summarize } from '../summary';
import type { AvEngine, AvFileResult, AvSummary, HashReputation } from '../types';
import { verdictOf } from '../engine';
import { clamScanFiles, detectClamAV, type ClamInfo } from './clamav';
import type { ScanTarget } from './locations';
import { walkTargets } from './walk';

export interface ScanPathsOptions {
  /** Bytes of each file the heuristics read. */
  heuristicBytes?: number;
  /** Files above this are listed as skipped (not hashed). Default 1 GiB. */
  maxFileBytes?: number;
  /** 'auto' uses ClamAV when installed; 'off' never; 'require' errors without it. */
  clamav?: 'auto' | 'off' | 'require';
  /** Send SHA-256 hashes of risky files to the reputation API. */
  reputation?: boolean;
  lookupEndpoint?: string;
  userAgent?: string;
  signatures?: SignatureSet;
  /** Extra `sha256 name` signature file. */
  signatureFile?: string;
  concurrency?: number;
  signal?: AbortSignal;
  onProgress?: (e: ScanProgress) => void;
}

export type ScanProgress =
  | { type: 'file'; path: string; scanned: number; result: AvFileResult }
  | { type: 'skip'; path: string; reason: string }
  | { type: 'phase'; phase: 'walking' | 'reputation' | 'clamav' | 'done'; detail?: string };

export interface ScanReport {
  summary: AvSummary;
  results: AvFileResult[];
  clamav: ClamInfo | null;
  clamavError: string | null;
  skipped: Array<{ path: string; reason: string }>;
}

/** File kinds worth a reputation lookup: things that run, or carry code. */
const LOOKUP_KINDS = new Set(['pe', 'elf', 'macho', 'script', 'lnk', 'ole', 'zip', 'pdf', 'dex', 'rtf']);
const MAX_LOOKUPS = 5000;

/** Stream a file once: full SHA-256 plus the first `cap` bytes for heuristics. */
export async function readForScan(path: string, size: number, cap: number): Promise<{ head: Uint8Array; sha256: string }> {
  const hash = createHash('sha256');
  const head = Buffer.allocUnsafe(Math.min(size, cap));
  let filled = 0;
  await new Promise<void>((resolve, reject) => {
    const s = createReadStream(path, { highWaterMark: 1 << 20 });
    s.on('data', (chunk) => {
      const c = chunk as Buffer;
      hash.update(c);
      if (filled < head.length) {
        const n = Math.min(head.length - filled, c.length);
        c.copy(head, filled, 0, n);
        filled += n;
      }
    });
    s.on('error', reject);
    s.on('end', () => resolve());
  });
  return { head: head.subarray(0, filled), sha256: hash.digest('hex') };
}

/** Scan files and folders. Never throws for a single bad file. */
export async function scanPaths(targets: ScanTarget[], opts: ScanPathsOptions = {}): Promise<ScanReport> {
  const started = new Date();
  const cap = opts.heuristicBytes ?? DEFAULT_HEURISTIC_BYTES;
  const maxFile = opts.maxFileBytes ?? 1024 ** 3;
  const skipped: Array<{ path: string; reason: string }> = [];
  const skip = (path: string, reason: string) => {
    skipped.push({ path, reason });
    opts.onProgress?.({ type: 'skip', path, reason });
  };

  let signatures = opts.signatures;
  if (opts.signatureFile && existsSync(opts.signatureFile)) {
    signatures = signatures ?? new SignatureSet();
    signatures.load(readFileSync(opts.signatureFile, 'utf8'));
  }

  const clamav = opts.clamav === 'off' ? null : await detectClamAV();
  if (opts.clamav === 'require' && !clamav?.available) throw new Error('ClamAV is not installed (or clamscan is not on PATH)');

  opts.onProgress?.({ type: 'phase', phase: 'walking' });
  const results: AvFileResult[] = [];
  const queue: Array<Promise<void>> = [];
  const limit = Math.max(1, opts.concurrency ?? 4);

  const scanOne = async (path: string, size: number) => {
    try {
      const { head, sha256 } = await readForScan(path, size, cap);
      const r = await scanBytes({ name: path, bytes: head, size, sha256 }, { signatures });
      results.push(r);
      opts.onProgress?.({ type: 'file', path, scanned: results.length, result: r });
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? (e as Error).message;
      const r: AvFileResult = { path, size, sha256: null, kind: 'unknown', verdict: 'error', detections: [], note: code };
      results.push(r);
      opts.onProgress?.({ type: 'file', path, scanned: results.length, result: r });
    }
  };

  for await (const f of walkTargets(targets, { signal: opts.signal, onSkip: skip })) {
    if (opts.signal?.aborted) break;
    if (f.size === 0) continue;
    if (f.size > maxFile) {
      skip(f.path, `larger than ${Math.round(maxFile / 1048576)} MB`);
      continue;
    }
    const p = scanOne(f.path, f.size).finally(() => {
      queue.splice(queue.indexOf(p), 1);
    });
    queue.push(p);
    if (queue.length >= limit) await Promise.race(queue);
  }
  await Promise.all(queue);

  const engines: AvEngine[] = ['signature', 'heuristic'];

  if (opts.reputation !== false && !opts.signal?.aborted) {
    const wanted = results
      .filter((r) => r.sha256 && (LOOKUP_KINDS.has(r.kind) || r.detections.length > 0))
      .slice(0, MAX_LOOKUPS);
    if (wanted.length) {
      opts.onProgress?.({ type: 'phase', phase: 'reputation', detail: `${wanted.length} hashes` });
      const reps = await lookupHashes(wanted.map((r) => r.sha256!), { endpoint: opts.lookupEndpoint, userAgent: opts.userAgent });
      if (reps.size || wanted.length) engines.push('reputation');
      applyAll(results, reps);
    }
  }

  let clamavError: string | null = null;
  if (clamav?.available && !opts.signal?.aborted) {
    const files = results.filter((r) => r.verdict !== 'error').map((r) => r.path);
    opts.onProgress?.({ type: 'phase', phase: 'clamav', detail: `${files.length} files via ${clamav.mode}` });
    const { detections, error } = await clamScanFiles(clamav, files, { signal: opts.signal });
    clamavError = error;
    if (!error) engines.push('clamav');
    for (const r of results) {
      const extra = detections.get(r.path);
      if (!extra) continue;
      r.detections.push(...extra);
      r.verdict = verdictOf(r.detections);
    }
  }

  opts.onProgress?.({ type: 'phase', phase: 'done' });
  return { summary: summarize(results, engines, started, skipped.length), results, clamav, clamavError, skipped };
}

function applyAll(results: AvFileResult[], reps: Map<string, HashReputation>): void {
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (r.sha256 && reps.has(r.sha256)) results[i] = applyReputation(r, reps.get(r.sha256));
  }
}
