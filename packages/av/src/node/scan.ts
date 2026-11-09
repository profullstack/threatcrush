import { createHash } from 'node:crypto';
import { createReadStream, readFileSync, existsSync } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { availableParallelism } from 'node:os';
import { Worker } from 'node:worker_threads';
import { applyReputation, DEFAULT_HEURISTIC_BYTES, scanBytes, SignatureSet } from '../engine';
import { lookupHashes } from '../reputation';
import { summarize } from '../summary';
import type { AvEngine, AvFileResult, AvSummary, HashReputation } from '../types';
import { verdictOf } from '../engine';
import { clamScanFiles, detectClamAV, type ClamInfo } from './clamav';
import type { ScanTarget } from './locations';
import type { FileOutcome } from './scan-file';
import type { ScanWorkerInit, ScanWorkerReply } from './scan-worker';
import { walkFiles } from './walk';

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
  /**
   * With `workerScript`: worker threads (default: one per CPU). Without: files
   * read at once on the calling thread (default 4).
   */
  concurrency?: number;
  /**
   * A file that calls `runScanWorker()` (bundled by the host). When set, files
   * are read, hashed and checked in parallel worker threads with blocking I/O,
   * which is many times faster on big trees. Without it everything runs on the
   * calling thread with async I/O (safe for an Electron main process).
   */
  workerScript?: string | URL;
  /**
   * Keep every clean result in `report.results` (default true). Set false for
   * big scans: clean files are only counted, so memory stays flat.
   */
  keepClean?: boolean;
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
  const keepClean = opts.keepClean !== false;
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
  // ClamAV re-reads every readable file, so it needs every path, clean or not.
  const clamFiles: string[] | null = clamav?.available ? [] : null;

  opts.onProgress?.({ type: 'phase', phase: 'walking' });
  const results: AvFileResult[] = [];
  let scanned = 0;
  let droppedClean = 0;
  let cleanLookupsKept = 0;

  const record = (r: AvFileResult) => {
    scanned++;
    if (clamFiles && r.verdict !== 'error') clamFiles.push(r.path);
    const keep =
      keepClean ||
      r.verdict !== 'clean' ||
      r.detections.length > 0 ||
      (r.sha256 !== null && LOOKUP_KINDS.has(r.kind) && cleanLookupsKept++ < MAX_LOOKUPS);
    if (keep) results.push(r);
    else droppedClean++;
    opts.onProgress?.({ type: 'file', path: r.path, scanned, result: r });
  };
  const take = (o: FileOutcome) => {
    if (o.kind === 'result') record(o.result);
    else if (o.kind === 'skip') skip(o.path, o.reason);
  };
  const walk = () => walkFiles(targets, { signal: opts.signal, onSkip: skip });

  if (opts.workerScript) {
    await scanInWorkers(walk(), {
      script: opts.workerScript,
      workers: Math.max(1, opts.concurrency ?? availableParallelism()),
      init: { cap, maxFile, signatures: signatures?.entries() },
      signal: opts.signal,
      take,
    });
  } else {
    const queue = new Set<Promise<void>>();
    const limit = Math.max(1, opts.concurrency ?? 4);
    const scanOne = async (path: string) => {
      let size: number;
      try {
        const st = await lstat(path);
        if (!st.isFile() || st.size === 0) return;
        size = st.size;
      } catch {
        return;
      }
      if (size > maxFile) return skip(path, `larger than ${Math.round(maxFile / 1048576)} MB`);
      try {
        const { head, sha256 } = await readForScan(path, size, cap);
        record(await scanBytes({ name: path, bytes: head, size, sha256 }, { signatures }));
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code ?? (e as Error).message;
        record({ path, size, sha256: null, kind: 'unknown', verdict: 'error', detections: [], note: code });
      }
    };
    for await (const path of walk()) {
      if (opts.signal?.aborted) break;
      const p: Promise<void> = scanOne(path).finally(() => queue.delete(p));
      queue.add(p);
      if (queue.size >= limit) await Promise.race(queue);
    }
    await Promise.all(queue);
  }

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
  if (clamav?.available && clamFiles && !opts.signal?.aborted) {
    opts.onProgress?.({ type: 'phase', phase: 'clamav', detail: `${clamFiles.length} files via ${clamav.mode}` });
    const { detections, error } = await clamScanFiles(clamav, clamFiles, { signal: opts.signal });
    clamavError = error;
    if (!error) engines.push('clamav');
    const byPath = new Map(results.map((r) => [r.path, r]));
    for (const [path, extra] of detections) {
      let r = byPath.get(path);
      if (!r) {
        // A clean file that was only counted: bring it back as a result.
        r = { path, size: 0, sha256: null, kind: 'unknown', verdict: 'clean', detections: [] };
        results.push(r);
        droppedClean--;
      }
      r.detections.push(...extra);
      r.verdict = verdictOf(r.detections);
    }
  }

  opts.onProgress?.({ type: 'phase', phase: 'done' });
  const summary = summarize(results, engines, started, skipped.length);
  summary.scanned += droppedClean;
  summary.clean += droppedClean;
  return { summary, results, clamav, clamavError, skipped };
}

/** Feed walked paths to a pool of scan workers in batches. */
async function scanInWorkers(
  paths: AsyncIterable<string>,
  o: { script: string | URL; workers: number; init: ScanWorkerInit; signal?: AbortSignal; take: (x: FileOutcome) => void },
): Promise<void> {
  const BATCH = 64;
  const PER_WORKER = 2;
  let failure: Error | null = null;
  const waiting = new Map<number, { resolve: (out: FileOutcome[]) => void; reject: (e: Error) => void }>();
  const fail = (e: Error) => {
    failure ??= e;
    for (const w of waiting.values()) w.reject(e);
    waiting.clear();
  };
  const slots = Array.from({ length: o.workers }, () => {
    const worker = new Worker(o.script, { workerData: o.init });
    worker.on('message', (m: ScanWorkerReply) => {
      const w = waiting.get(m.id);
      waiting.delete(m.id);
      w?.resolve(m.out);
    });
    worker.on('error', fail);
    worker.on('exit', (code) => {
      if (code !== 0) fail(new Error(`scan worker exited with code ${code}`));
    });
    return { worker, busy: 0 };
  });

  let nextId = 0;
  const inflight = new Set<Promise<void>>();
  const send = (files: string[]) => {
    const slot = slots.reduce((a, b) => (b.busy < a.busy ? b : a));
    slot.busy++;
    const id = nextId++;
    const p: Promise<void> = new Promise<FileOutcome[]>((resolve, reject) => waiting.set(id, { resolve, reject }))
      .then((out) => {
        for (const x of out) o.take(x);
      })
      .finally(() => {
        slot.busy--;
        inflight.delete(p);
      });
    inflight.add(p);
    slot.worker.postMessage({ id, files });
  };

  try {
    let batch: string[] = [];
    for await (const path of paths) {
      if (failure) throw failure;
      if (o.signal?.aborted) break;
      batch.push(path);
      if (batch.length < BATCH) continue;
      send(batch);
      batch = [];
      while (inflight.size >= o.workers * PER_WORKER) await Promise.race(inflight);
    }
    if (batch.length && !o.signal?.aborted) send(batch);
    await Promise.all(inflight);
    if (failure) throw failure;
  } finally {
    // Swallow rejections from batches we are abandoning on the way out.
    for (const p of inflight) p.catch(() => {});
    slots.forEach((s) => s.worker.removeAllListeners('exit'));
    await Promise.all(slots.map((s) => s.worker.terminate()));
  }
}

function applyAll(results: AvFileResult[], reps: Map<string, HashReputation>): void {
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (r.sha256 && reps.has(r.sha256)) results[i] = applyReputation(r, reps.get(r.sha256));
  }
}
