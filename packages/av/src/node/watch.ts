import { watch, type FSWatcher } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { applyReputation, scanBytes, type SignatureSet } from '../engine';
import { lookupHashes } from '../reputation';
import type { AvFileResult } from '../types';
import type { ScanTarget } from './locations';
import { readForScan } from './scan';
import { SKIP_DIR_NAMES } from './walk';

export interface WatchOptions {
  /** Wait this long after the last change before scanning (downloads arrive in chunks). */
  settleMs?: number;
  heuristicBytes?: number;
  maxFileBytes?: number;
  reputation?: boolean;
  lookupEndpoint?: string;
  signatures?: SignatureSet;
  onResult: (r: AvFileResult) => void;
  onError?: (path: string, err: Error) => void;
}

/** Partial-download names browsers use while a file is still arriving. */
const IN_PROGRESS = /\.(?:crdownload|part|partial|download|tmp)$/i;

/**
 * Real-time protection: scan files as they appear or change under the
 * targets. Returns a stop function. Uses the OS file-change API (recursive
 * watching works on Windows, macOS and, from Node 20, Linux).
 */
export function watchTargets(targets: ScanTarget[], opts: WatchOptions): () => void {
  const settle = opts.settleMs ?? 1500;
  const timers = new Map<string, ReturnType<typeof setTimeout>>();
  const lastScanned = new Map<string, string>();
  const watchers: FSWatcher[] = [];

  const scan = async (path: string) => {
    timers.delete(path);
    try {
      const st = await lstat(path);
      if (!st.isFile() || st.size === 0 || st.size > (opts.maxFileBytes ?? 1024 ** 3)) return;
      const key = `${st.size}:${st.mtimeMs}`;
      if (lastScanned.get(path) === key) return;
      lastScanned.set(path, key);
      if (lastScanned.size > 10_000) lastScanned.delete(lastScanned.keys().next().value as string);
      const { head, sha256 } = await readForScan(path, st.size, opts.heuristicBytes ?? 16 * 1024 * 1024);
      let r = await scanBytes({ name: path, bytes: head, size: st.size, sha256 }, { signatures: opts.signatures });
      if (opts.reputation !== false) {
        const reps = await lookupHashes([sha256], { endpoint: opts.lookupEndpoint, timeoutMs: 8000 });
        r = applyReputation(r, reps.get(sha256));
      }
      opts.onResult(r);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') opts.onError?.(path, e as Error);
    }
  };

  for (const t of targets) {
    try {
      const w = watch(t.path, { recursive: t.depth > 1, persistent: true }, (_event, file) => {
        if (!file) return;
        const rel = String(file);
        if (IN_PROGRESS.test(rel)) return;
        const parts = rel.split(/[\\/]/);
        if (parts.length > t.depth || parts.some((p) => SKIP_DIR_NAMES.has(p))) return;
        const full = join(t.path, rel);
        const prev = timers.get(full);
        if (prev) clearTimeout(prev);
        timers.set(full, setTimeout(() => void scan(full), settle));
      });
      w.on('error', (e) => opts.onError?.(t.path, e));
      watchers.push(w);
    } catch (e) {
      opts.onError?.(t.path, e as Error);
    }
  }

  return () => {
    for (const w of watchers) w.close();
    for (const tm of timers.values()) clearTimeout(tm);
    timers.clear();
  };
}
