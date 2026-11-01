import { constants, type FileHandle, lstat, open, readdir, readFile, rename, mkdir, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, isAbsolute, join, normalize, sep } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';
import type { FileIntegritySection } from '../../types/config.js';
import { insertEvent } from '../../core/state.js';

const DEFAULT_POLL_MS = 15 * 60_000;
const MAX_FILES = 50_000;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_SCAN_BYTES = 512 * 1024 * 1024;
const MAX_CHANGES_PER_EVENT = 100;
const MASS_CHANGE_COUNT = 25;
const READ_CHUNK_BYTES = 64 * 1024;

interface FileSignature {
  sha256: string;
  size: number;
  mode: number;
  uid: number;
  gid: number;
}

type FileState = string | 'missing';

interface IntegrityState {
  schema: 1;
  created_at: string;
  targets: string[];
  files: Record<string, FileState>;
}

interface ScanResult {
  files: Record<string, FileState>;
  complete: boolean;
  skipped: number;
  bytes: number;
  errorPaths: string[];
}

export interface FileIntegritySettings {
  enabled: boolean;
  paths: string[];
  canaries: string[];
  pollMs: number;
}

export function fileIntegritySettings(section: FileIntegritySection | undefined): FileIntegritySettings {
  const safePath = (value: unknown): string | null => {
    if (typeof value !== 'string' || !isAbsolute(value) || value.split(sep).includes('..')) return null;
    const path = normalize(value);
    return path === '/' ? null : path;
  };
  const strings = (values: unknown): string[] => Array.isArray(values)
    ? [...new Set(values.map(safePath).filter((path): path is string => path !== null))]
    : [];
  const configuredSeconds = section?.poll_interval_seconds;
  const pollMs = typeof configuredSeconds === 'number' && Number.isFinite(configuredSeconds)
    ? Math.max(60, Math.min(86_400, Math.floor(configuredSeconds))) * 1000
    : DEFAULT_POLL_MS;
  return {
    // File scans read disk contents (only to hash them), so make this explicit
    // instead of adding an unannounced I/O load to existing installations.
    enabled: section?.enabled === true,
    paths: strings(section?.paths),
    canaries: strings(section?.canaries),
    pollMs,
  };
}

export interface FileIntegrityOptions {
  bus: { publish(event: ThreatEvent): void };
  baselinePath: string;
  observedPath: string;
  settings: FileIntegritySettings;
  log: (line: string) => void;
  now?: () => Date;
}

function signature(value: FileSignature): string {
  return `${value.sha256};size=${value.size};mode=${value.mode.toString(8)};uid=${value.uid};gid=${value.gid}`;
}

async function readState(path: string): Promise<IntegrityState | null> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as IntegrityState;
    if (parsed.schema !== 1 || !Array.isArray(parsed.targets) || !parsed.files || typeof parsed.files !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeState(path: string, state: IntegrityState): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temp, JSON.stringify(state), { mode: 0o600 });
  await rename(temp, path);
}

async function hashFile(path: string, handle: FileHandle, size: number): Promise<string> {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(READ_CHUNK_BYTES);
  let position = 0;
  while (position < size) {
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, size - position), position);
    if (bytesRead === 0) throw new Error(`file changed while reading: ${path}`);
    hash.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return hash.digest('hex');
}

async function scanTargets(targets: string[], canaries: Set<string>): Promise<ScanResult> {
  const files: Record<string, FileState> = {};
  const visited = new Set<string>();
  const errors = new Set<string>();
  let complete = true;
  let skipped = 0;
  let bytes = 0;

  const walk = async (path: string): Promise<void> => {
    if (visited.has(path) || !complete) return;
    visited.add(path);
    if (visited.size > MAX_FILES) {
      complete = false;
      errors.add(path);
      return;
    }

    let stat;
    try {
      stat = await lstat(path);
    } catch (error) {
      // An absent explicitly configured canary is a meaningful state. Other
      // disappearing files can be a race during an update, so don't baseline
      // from an incomplete traversal.
      if ((error as NodeJS.ErrnoException).code === 'ENOENT' && targets.includes(path)) files[path] = 'missing';
      else {
        complete = false;
        errors.add(path);
      }
      return;
    }
    if (stat.isSymbolicLink()) {
      skipped++;
      return;
    }
    if (stat.isDirectory()) {
      let entries;
      try {
        entries = await readdir(path, { withFileTypes: true });
      } catch {
        complete = false;
        errors.add(path);
        return;
      }
      for (const entry of entries) {
        await walk(join(path, entry.name));
        if (!complete) return;
      }
      return;
    }
    if (!stat.isFile()) {
      skipped++;
      return;
    }
    if (stat.size > MAX_FILE_BYTES || bytes + stat.size > MAX_SCAN_BYTES) {
      complete = false;
      errors.add(path);
      return;
    }

    let handle: FileHandle | undefined;
    try {
      // O_NOFOLLOW closes the lstat/open race for the file itself. No file
      // content is retained; each descriptor is read only to compute SHA-256.
      handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const opened = await handle.stat();
      if (!opened.isFile() || opened.size !== stat.size) throw new Error('file changed while opening');
      const sha256 = await hashFile(path, handle, opened.size);
      bytes += opened.size;
      files[path] = signature({
        sha256,
        size: opened.size,
        mode: opened.mode & 0o7777,
        uid: opened.uid,
        gid: opened.gid,
      });
    } catch {
      complete = false;
      errors.add(path);
    } finally {
      await handle?.close().catch(() => undefined);
    }
  };

  for (const target of targets) {
    let targetStat;
    try {
      targetStat = await lstat(target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') files[target] = 'missing';
      else {
        complete = false;
        errors.add(target);
      }
      continue;
    }
    if (targetStat.isSymbolicLink()) {
      if (canaries.has(target)) {
        complete = false;
        errors.add(target);
      } else skipped++;
      continue;
    }
    if (targetStat.isDirectory() && canaries.has(target)) {
      complete = false;
      errors.add(target);
    } else if (visited.has(target)) {
      continue;
    } else if (targetStat.isDirectory()) await walk(target);
    else if (targetStat.isFile()) await walk(target);
    else skipped++;
    if (!complete) break;
  }

  return { files, complete, skipped, bytes, errorPaths: [...errors].slice(0, 20) };
}

function changedPaths(before: Record<string, FileState>, after: Record<string, FileState>): Array<{ path: string; state: FileState }> {
  const paths = new Set([...Object.keys(before), ...Object.keys(after)]);
  const changed: Array<{ path: string; state: FileState }> = [];
  for (const path of paths) {
    const previous = before[path] ?? 'missing';
    const current = after[path] ?? 'missing';
    if (previous !== current) changed.push({ path, state: current });
  }
  return changed;
}

export class FileIntegrityWatch {
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private readonly now: () => Date;
  private readonly canaries: Set<string>;

  constructor(private readonly opts: FileIntegrityOptions) {
    this.now = opts.now ?? (() => new Date());
    this.canaries = new Set(opts.settings.canaries);
  }

  start(): void {
    if (!this.opts.settings.enabled) {
      this.opts.log('[file-integrity] disabled; set [file_integrity] enabled = true to monitor configured paths');
      return;
    }
    const targets = [...new Set([...this.opts.settings.paths, ...this.opts.settings.canaries])];
    if (targets.length === 0) {
      this.opts.log('[file-integrity] enabled with no paths; configure [file_integrity] paths or canaries');
      return;
    }
    this.opts.log(`[file-integrity] monitoring ${targets.length} configured path(s), polling every ${Math.round(this.opts.settings.pollMs / 60_000)}m; content is hashed locally`);
    void this.scanOnce();
    this.timer = setInterval(() => { void this.scanOnce(); }, this.opts.settings.pollMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async rebaseline(): Promise<{ ok: boolean; files: number; reason?: string }> {
    const targets = [...new Set([...this.opts.settings.paths, ...this.opts.settings.canaries])];
    if (!this.opts.settings.enabled || targets.length === 0) return { ok: false, files: 0, reason: 'file integrity monitoring is disabled or has no configured paths' };
    const scan = await scanTargets(targets, this.canaries);
    if (!scan.complete) return { ok: false, files: Object.keys(scan.files).length, reason: `scan incomplete at ${scan.errorPaths.join(', ') || 'configured size limit'}` };
    const missingCanary = [...this.canaries].find((path) => scan.files[path] === 'missing');
    if (missingCanary) return { ok: false, files: Object.keys(scan.files).length, reason: `configured canary does not exist: ${missingCanary}` };
    const state: IntegrityState = { schema: 1, created_at: this.now().toISOString(), targets, files: scan.files };
    await writeState(this.opts.baselinePath, state);
    await writeState(this.opts.observedPath, state);
    return { ok: true, files: Object.keys(scan.files).length };
  }

  private async scanOnce(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const targets = [...new Set([...this.opts.settings.paths, ...this.opts.settings.canaries])];
      const current = await scanTargets(targets, this.canaries);
      if (!current.complete) {
        this.opts.log(`[file-integrity] scan incomplete; no baseline or change state updated (${current.errorPaths.join(', ') || 'configured scan limits reached'})`);
        return;
      }

      const baseline = await readState(this.opts.baselinePath);
      if (!baseline) {
        // A missing state file means first enrollment. A present but unreadable
        // or malformed baseline must never be silently replaced: that would
        // turn tampering into the new expected state.
        let baselineFilePresent = false;
        try {
          await lstat(this.opts.baselinePath);
          baselineFilePresent = true;
        } catch (error) {
          baselineFilePresent = (error as NodeJS.ErrnoException).code !== 'ENOENT';
        }
        if (baselineFilePresent) {
          this.emit('critical', 'File integrity baseline is unreadable; monitoring paused', 'file-integrity-baseline-invalid', [
            { path: this.opts.baselinePath, state: 'unreadable' },
          ]);
          this.opts.log('[file-integrity] baseline is present but unreadable; it was not replaced');
          return;
        }
        const missingCanary = [...this.canaries].find((path) => current.files[path] === 'missing');
        if (missingCanary) {
          this.opts.log(`[file-integrity] cannot record baseline; configured canary does not exist: ${missingCanary}`);
          return;
        }
        const created: IntegrityState = { schema: 1, created_at: this.now().toISOString(), targets, files: current.files };
        await writeState(this.opts.baselinePath, created);
        await writeState(this.opts.observedPath, created);
        this.opts.log(`[file-integrity] initial baseline recorded for ${Object.keys(current.files).length} file(s)`);
        return;
      }

      const observed = await readState(this.opts.observedPath) ?? baseline;
      const sameTargets = (left: string[], right: string[]) => {
        const sortedLeft = [...left].sort();
        const sortedRight = [...right].sort();
        return sortedLeft.length === sortedRight.length && sortedLeft.every((path, index) => path === sortedRight[index]);
      };
      if (!sameTargets(baseline.targets, targets)) {
        if (!sameTargets(observed.targets, targets)) {
          this.emit('medium', 'File integrity monitoring paths changed; review them and rebaseline', 'file-integrity-scope-changed',
            targets.map((path) => ({ path, state: 'scope-changed' })));
        }
        await writeState(this.opts.observedPath, { schema: 1, created_at: observed.created_at, targets, files: current.files });
        return;
      }
      const changes = changedPaths(observed.files, current.files);
      const canaryChanges = changes.filter((change) => this.canaries.has(change.path));
      if (canaryChanges.length) {
        this.emit('critical', 'A file integrity canary changed or disappeared', 'file-integrity-canary', canaryChanges);
      }
      const ordinary = changes.filter((change) => !this.canaries.has(change.path));
      if (ordinary.length >= MASS_CHANGE_COUNT) {
        this.emit('critical', `${ordinary.length} monitored files changed in one scan`, 'file-integrity-mass-change', ordinary);
      } else {
        for (const change of ordinary) {
          const expected = baseline.files[change.path] ?? 'missing';
          const restored = change.state === expected;
          this.emit(restored ? 'low' : 'high', restored
            ? `Monitored file returned to its baseline: ${change.path}`
            : `Monitored file changed: ${change.path}`,
          restored ? 'file-integrity-restored' : 'file-integrity-changed', [change]);
        }
      }

      const nextObserved: IntegrityState = { schema: 1, created_at: observed.created_at, targets, files: current.files };
      await writeState(this.opts.observedPath, nextObserved);
    } catch (error) {
      this.opts.log(`[file-integrity] scan failed: ${(error as Error).message.split('\n')[0]}`);
    } finally {
      this.running = false;
    }
  }

  private emit(
    severity: ThreatEvent['severity'],
    message: string,
    ruleId: string,
    changes: Array<{ path: string; state: FileState }>,
  ): void {
    const event: ThreatEvent = {
      timestamp: this.now(),
      module: 'file-integrity',
      category: 'system',
      severity,
      message: message.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500),
      details: {
        rule_id: ruleId,
        change_count: changes.length,
        changes: changes.slice(0, MAX_CHANGES_PER_EVENT).map(({ path, state }) => ({
          path,
          state: state === 'missing' ? 'missing' : 'present',
        })),
        truncated: changes.length > MAX_CHANGES_PER_EVENT,
      },
    };
    try { insertEvent(event); } catch { /* state DB is optional */ }
    this.opts.bus.publish(event);
  }
}
