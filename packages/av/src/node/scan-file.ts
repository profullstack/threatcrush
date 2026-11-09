import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { scanBytes, type SignatureSet } from '../engine';
import type { AvFileResult } from '../types';

/**
 * Scan one file with synchronous I/O. Meant for worker threads: a sync read
 * costs no libuv thread-pool hop (that pool is 4 threads per process, which
 * otherwise caps every async file read in the scan at 4 at a time), and
 * blocking a worker blocks nothing else.
 */

export type FileOutcome =
  | { kind: 'result'; result: AvFileResult }
  | { kind: 'skip'; path: string; reason: string }
  | { kind: 'none' };

export interface ScanFileOptions {
  /** Bytes of the file the heuristics see. */
  cap: number;
  /** Larger files are skipped, not hashed. */
  maxFile: number;
  signatures?: SignatureSet;
}

const CHUNK = 1 << 20;
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

// Reused across calls; one scanner per thread, and calls are serialised.
let head: Buffer = Buffer.allocUnsafe(64 * 1024);
let chunk: Buffer | null = null;

export async function scanFileSync(path: string, opts: ScanFileOptions): Promise<FileOutcome> {
  let fd: number;
  try {
    fd = openSync(path, OPEN_FLAGS);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? 'unreadable';
    // Gone between the directory listing and now, or a symlink swapped in: nothing to scan.
    if (code === 'ENOENT' || code === 'ELOOP') return { kind: 'none' };
    return { kind: 'result', result: errorResult(path, 0, code) };
  }
  let size = 0;
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size === 0) return { kind: 'none' };
    size = st.size;
    if (size > opts.maxFile) return { kind: 'skip', path, reason: `larger than ${Math.round(opts.maxFile / 1048576)} MB` };

    const want = Math.min(size, opts.cap);
    if (head.length < want) head = Buffer.allocUnsafe(Math.max(want, head.length * 2 > opts.cap ? want : head.length * 2));
    const hash = createHash('sha256');
    let filled = 0;
    while (filled < want) {
      const n = readSync(fd, head, filled, want - filled, null);
      if (n === 0) break;
      filled += n;
    }
    hash.update(head.subarray(0, filled));
    let total = filled;
    if (filled === want && size > want) {
      chunk ??= Buffer.allocUnsafe(CHUNK);
      for (;;) {
        const n = readSync(fd, chunk, 0, CHUNK, null);
        if (n === 0) break;
        hash.update(chunk.subarray(0, n));
        total += n;
      }
    }
    const result = await scanBytes(
      { name: path, bytes: head.subarray(0, filled), size: total, sha256: hash.digest('hex') },
      { signatures: opts.signatures },
    );
    return { kind: 'result', result };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? (e as Error).message;
    return { kind: 'result', result: errorResult(path, size, code) };
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* already closed */
    }
  }
}

function errorResult(path: string, size: number, note: string): AvFileResult {
  return { path, size, sha256: null, kind: 'unknown', verdict: 'error', detections: [], note };
}
