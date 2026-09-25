import { mkdirSync, readFileSync } from 'node:fs';
import { appendFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export interface SpoolLimits {
  maxEvents: number;
  maxBytes: number;
}

export const DEFAULT_SPOOL_LIMITS: SpoolLimits = { maxEvents: 10_000, maxBytes: 20 * 1024 * 1024 };

/**
 * The upload queue, mirrored to a JSONL file so events survive a restart or an
 * outage of the dashboard.
 *
 * Bounded: past `maxEvents` or `maxBytes` the oldest events go, because on a
 * box under a sustained attack with the network down the newest evidence is
 * the useful part and a full disk helps nobody.
 *
 * Every mutation is in memory first and written to disk afterwards, on a
 * promise chain, so a detection never waits on the filesystem. Appends are the
 * common case; the file is only rewritten (tmp + rename) after events are
 * acknowledged or dropped.
 */
export class CloudSpool {
  private lines: string[] = [];
  private bytes = 0;
  private pendingAppend: string[] = [];
  private needsRewrite = false;
  private scheduled = false;
  private writes: Promise<void> = Promise.resolve();
  private droppedSinceReport = 0;

  constructor(private path: string, private limits: SpoolLimits = DEFAULT_SPOOL_LIMITS) {
    try { mkdirSync(dirname(path), { recursive: true }); } catch { /* reported on write */ }
    this.load();
  }

  get size(): number { return this.lines.length; }

  push(event: object): void {
    const line = JSON.stringify(event);
    this.lines.push(line);
    this.bytes += Buffer.byteLength(line) + 1;
    this.pendingAppend.push(line);
    this.enforceLimits();
    this.schedule();
  }

  /** Up to `maxEvents` of the oldest events whose JSON fits in `maxBytes`. */
  peek(maxEvents: number, maxBytes: number): object[] {
    const out: object[] = [];
    let bytes = 0;
    for (const line of this.lines) {
      if (out.length >= maxEvents) break;
      const size = Buffer.byteLength(line) + 1;
      // Always return at least one, or a single oversized event would wedge the queue.
      if (out.length > 0 && bytes + size > maxBytes) break;
      bytes += size;
      out.push(JSON.parse(line) as object);
    }
    return out;
  }

  /** Forget the `count` oldest events: they were delivered or will never be. */
  ack(count: number): void {
    if (count <= 0) return;
    for (const line of this.lines.splice(0, count)) this.bytes -= Buffer.byteLength(line) + 1;
    this.needsRewrite = true;
    this.schedule();
  }

  /** Events dropped by the bound since the last call, for a single log line. */
  takeDropped(): number {
    const n = this.droppedSinceReport;
    this.droppedSinceReport = 0;
    return n;
  }

  /** Resolves once everything queued so far is on disk. */
  settled(): Promise<void> { return this.writes; }

  private enforceLimits(): void {
    let dropped = 0;
    while (
      this.lines.length > 0 &&
      (this.lines.length > this.limits.maxEvents || this.bytes > this.limits.maxBytes)
    ) {
      this.bytes -= Buffer.byteLength(this.lines.shift()!) + 1;
      dropped++;
    }
    if (dropped > 0) {
      this.droppedSinceReport += dropped;
      this.needsRewrite = true;
    }
  }

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.path, 'utf-8');
    } catch {
      return;
    }
    let invalid = false;
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try {
        JSON.parse(line);
      } catch {
        // A line cut short by a crash mid-append.
        invalid = true;
        continue;
      }
      this.lines.push(line);
      this.bytes += Buffer.byteLength(line) + 1;
    }
    this.enforceLimits();
    if (invalid) this.needsRewrite = true;
    if (this.needsRewrite) this.schedule();
  }

  private schedule(): void {
    if (this.scheduled) return;
    this.scheduled = true;
    this.writes = this.writes
      .then(async () => {
        this.scheduled = false;
        if (this.needsRewrite) {
          this.needsRewrite = false;
          this.pendingAppend = [];
          const body = this.lines.length > 0 ? `${this.lines.join('\n')}\n` : '';
          const tmp = `${this.path}.tmp`;
          await writeFile(tmp, body, { mode: 0o600 });
          await rename(tmp, this.path);
        } else if (this.pendingAppend.length > 0) {
          const chunk = `${this.pendingAppend.join('\n')}\n`;
          this.pendingAppend = [];
          await appendFile(this.path, chunk, { mode: 0o600 });
        }
      })
      // Memory still holds the queue; the next change rewrites the file whole.
      .catch(() => { this.needsRewrite = true; });
  }
}
