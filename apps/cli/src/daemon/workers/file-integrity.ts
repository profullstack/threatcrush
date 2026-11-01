import { watch, type FSWatcher } from 'node:fs';
import { constants, type FileHandle, lstat, open, readdir, readFile, rename, mkdir, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { basename, dirname, isAbsolute, join, normalize, sep } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';
import type { FileIntegritySection } from '../../types/config.js';
import { insertEvent } from '../../core/state.js';

const DEFAULT_POLL_MS = 15 * 60_000;
const MAX_FILES = 50_000;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_SCAN_BYTES = 512 * 1024 * 1024;
const MAX_CHANGES_PER_EVENT = 100;
const MAX_WATCH_DIRECTORIES = 2048;
const MASS_CHANGE_COUNT = 25;
const MASS_CHANGE_ENTROPY_RISE_BITS = 0.5;
const READ_CHUNK_BYTES = 64 * 1024;
const CANARY_CONTENT = 'ThreatCrush file integrity canary v1\n';

interface FileSignature {
  sha256: string;
  entropy: number;
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
  directories: string[];
  complete: boolean;
  skipped: number;
  bytes: number;
  errorPaths: string[];
}

export interface FileIntegritySettings {
  enabled: boolean;
  paths: string[];
  canaries: string[];
  canaryDirectories: string[];
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
    canaryDirectories: strings(section?.canary_directories),
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
  return `${value.sha256};size=${value.size};mode=${value.mode.toString(8)};uid=${value.uid};gid=${value.gid};entropy=${value.entropy.toFixed(3)}`;
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

async function hashFile(path: string, handle: FileHandle, size: number): Promise<{ sha256: string; entropy: number }> {
  const hash = createHash('sha256');
  const buffer = Buffer.alloc(READ_CHUNK_BYTES);
  const counts = new Uint32Array(256);
  let position = 0;
  while (position < size) {
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, size - position), position);
    if (bytesRead === 0) throw new Error(`file changed while reading: ${path}`);
    const chunk = buffer.subarray(0, bytesRead);
    hash.update(chunk);
    for (const byte of chunk) counts[byte]++;
    position += bytesRead;
  }
  let entropy = 0;
  if (size > 0) for (const count of counts) {
    if (count === 0) continue;
    const probability = count / size;
    entropy -= probability * Math.log2(probability);
  }
  return { sha256: hash.digest('hex'), entropy };
}

const OPEN_FILE_FLAGS = constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW ?? 0);
const OPEN_DIR_FLAGS = OPEN_FILE_FLAGS | constants.O_DIRECTORY;
const CREATE_FILE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;

export function autoCanaryPath(directory: string): string {
  return join(directory, '.threatcrush-canary');
}

async function openAbsoluteDirectory(path: string): Promise<FileHandle> {
  const parts = path.split(sep).filter((part) => part && part !== '.');
  if (parts.includes('..')) throw new Error('invalid canary directory');
  let directory = await open('/', OPEN_DIR_FLAGS);
  try {
    for (const part of parts) {
      const next = await open(`/proc/self/fd/${directory.fd}/${part}`, OPEN_DIR_FLAGS);
      await directory.close();
      directory = next;
    }
    return directory;
  } catch (error) {
    await directory.close().catch(() => undefined);
    throw error;
  }
}

/** Create a harmless decoy without following symlinks or replacing existing data. */
async function createAutoCanary(path: string): Promise<boolean> {
  try {
    const existing = await openAbsoluteTarget(path);
    await existing.close();
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return false;
  }
  const directory = await openAbsoluteDirectory(dirname(path));
  try {
    const file = await open(`/proc/self/fd/${directory.fd}/${basename(path)}`, CREATE_FILE_FLAGS, 0o666);
    try { await file.chmod(0o666); await file.writeFile(CANARY_CONTENT); await file.sync(); }
    finally { await file.close(); }
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw error;
  } finally {
    await directory.close();
  }
}

/** Open an absolute path one no-follow directory descriptor at a time. */
async function openAbsoluteTarget(path: string): Promise<FileHandle> {
  const parts = path.split(sep).filter((part) => part && part !== '.');
  if (parts.length === 0 || parts.includes('..')) throw new Error('invalid file integrity path');
  let directory = await open('/', OPEN_DIR_FLAGS);
  try {
    for (const part of parts.slice(0, -1)) {
      const next = await open(`/proc/self/fd/${directory.fd}/${part}`, OPEN_DIR_FLAGS);
      await directory.close();
      directory = next;
    }
    const target = await open(`/proc/self/fd/${directory.fd}/${parts.at(-1)}`, OPEN_FILE_FLAGS);
    await directory.close();
    return target;
  } catch (error) {
    await directory.close().catch(() => undefined);
    throw error;
  }
}

async function scanTargets(targets: string[], canaries: Set<string>): Promise<ScanResult> {
  const files: Record<string, FileState> = {};
  const directories: string[] = [];
  const visited = new Set<string>();
  const errors = new Set<string>();
  let complete = true;
  let skipped = 0;
  let bytes = 0;

  const walk = async (path: string, parent?: FileHandle): Promise<void> => {
    if (visited.has(path) || !complete) return;
    visited.add(path);
    if (visited.size > MAX_FILES) {
      complete = false;
      errors.add(path);
      return;
    }

    let handle: FileHandle | undefined;
    try {
      // Keep the containing directory open while resolving a child. The path
      // passed to open is therefore rooted at that descriptor, and O_NOFOLLOW
      // rejects a symlink substituted for the final component.
      handle = parent
        ? await open(`/proc/self/fd/${parent.fd}/${path.slice(path.lastIndexOf(sep) + 1)}`, OPEN_FILE_FLAGS)
        : await openAbsoluteTarget(path);
      const stat = await handle.stat();
      if (stat.isDirectory()) {
        directories.push(path);
        if (canaries.has(path)) {
          complete = false;
          errors.add(path);
          return;
        }
        let entries;
        try {
          entries = await readdir(`/proc/self/fd/${handle.fd}`, { withFileTypes: true });
        } catch {
          complete = false;
          errors.add(path);
          return;
        }
        for (const entry of entries) {
          await walk(join(path, entry.name), handle);
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

      const { sha256, entropy } = await hashFile(path, handle, stat.size);
      const afterRead = await handle.stat();
      if (afterRead.size !== stat.size || afterRead.mtimeMs !== stat.mtimeMs || afterRead.ctimeMs !== stat.ctimeMs) {
        throw new Error('file changed while reading');
      }
      bytes += stat.size;
      files[path] = signature({
        sha256,
        entropy,
        size: stat.size,
        mode: stat.mode & 0o7777,
        uid: stat.uid,
        gid: stat.gid,
      });
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      // A missing explicit target is an observable state. A missing child
      // during traversal means the directory changed mid-scan, so don't use
      // this partial inventory.
      if (code === 'ENOENT' && targets.includes(path)) files[path] = 'missing';
      else if (code === 'ELOOP' && !canaries.has(path)) skipped++;
      else if (code === 'ENOENT' || code === 'ELOOP') {
        complete = false;
        errors.add(path);
      }
      else {
        complete = false;
        errors.add(path);
      }
    } finally {
      await handle?.close().catch(() => undefined);
    }
  };

  for (const target of targets) {
    await walk(target);
    if (!complete) break;
  }

  return { files, directories, complete, skipped, bytes, errorPaths: [...errors].slice(0, 20) };
}

function changedPaths(before: Record<string, FileState>, after: Record<string, FileState>): Array<{ path: string; state: FileState }> {
  const paths = new Set([...Object.keys(before), ...Object.keys(after)]);
  const changed: Array<{ path: string; state: FileState }> = [];
  for (const path of paths) {
    const previous = before[path] ?? 'missing';
    const current = after[path] ?? 'missing';
    const normalized = (value: FileState) => typeof value === 'string' ? value.replace(/;entropy=\d+(?:\.\d+)?$/, '') : value;
    if (normalized(previous) !== normalized(current)) changed.push({ path, state: current });
  }
  return changed;
}

function meanEntropy(paths: string[], files: Record<string, FileState>): number | null {
  const values = paths.flatMap((path) => {
    const signature = files[path];
    if (typeof signature !== 'string') return [];
    const match = /;entropy=(\d+(?:\.\d+)?)$/.exec(signature);
    return match ? [Number(match[1])] : [];
  });
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
}

export class FileIntegrityWatch {
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private readonly now: () => Date;
  private readonly canaries: Set<string>;
  private readonly watchers = new Map<string, FSWatcher>();
  private eventTimer: NodeJS.Timeout | null = null;
  private watcherLimitLogged = false;

  constructor(private readonly opts: FileIntegrityOptions) {
    this.now = opts.now ?? (() => new Date());
    this.canaries = new Set([
      ...opts.settings.canaries,
      ...opts.settings.canaryDirectories.map(autoCanaryPath),
    ]);
  }

  private get autoCanaries(): string[] {
    return this.opts.settings.canaryDirectories.map(autoCanaryPath);
  }

  private async ensureAutoCanaries(allowed: Set<string>): Promise<void> {
    for (const path of this.autoCanaries) {
      if (!allowed.has(path)) continue;
      try {
        if (await createAutoCanary(path)) this.opts.log(`[file-integrity] placed a canary at ${path}`);
      } catch (error) {
        this.opts.log(`[file-integrity] could not place canary at ${path}: ${(error as Error).message.split('\n')[0]}`);
      }
    }
  }

  start(): void {
    if (!this.opts.settings.enabled) {
      this.opts.log('[file-integrity] disabled; set [file_integrity] enabled = true to monitor configured paths');
      return;
    }
    const targets = [...new Set([...this.opts.settings.paths, ...this.opts.settings.canaries, ...this.autoCanaries])];
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
    if (this.eventTimer) clearTimeout(this.eventTimer);
    this.eventTimer = null;
    for (const watcher of this.watchers.values()) watcher.close();
    this.watchers.clear();
  }

  private refreshWatchers(directories: string[]): void {
    const wanted = new Set(directories.slice(0, MAX_WATCH_DIRECTORIES));
    for (const [path, watcher] of this.watchers) {
      if (wanted.has(path)) continue;
      watcher.close();
      this.watchers.delete(path);
    }
    for (const path of wanted) {
      if (this.watchers.has(path)) continue;
      try {
        const watcher = watch(path, { persistent: false }, () => {
          if (this.eventTimer) clearTimeout(this.eventTimer);
          this.eventTimer = setTimeout(() => { this.eventTimer = null; void this.scanOnce(); }, 500);
          this.eventTimer.unref?.();
        });
        watcher.on('error', (error) => {
          this.opts.log(`[file-integrity] inotify watch unavailable for ${path}: ${error.message}`);
          watcher.close();
          this.watchers.delete(path);
        });
        this.watchers.set(path, watcher);
      } catch (error) {
        this.opts.log(`[file-integrity] inotify watch unavailable for ${path}: ${(error as Error).message.split('\n')[0]}`);
      }
    }
    if (directories.length > MAX_WATCH_DIRECTORIES && !this.watcherLimitLogged) {
      this.watcherLimitLogged = true;
      this.opts.log(`[file-integrity] watching the first ${MAX_WATCH_DIRECTORIES} directories; polling remains the fallback for the rest`);
    }
  }

  async rebaseline(): Promise<{ ok: boolean; files: number; reason?: string }> {
    const targets = [...new Set([...this.opts.settings.paths, ...this.opts.settings.canaries, ...this.autoCanaries])];
    if (!this.opts.settings.enabled || targets.length === 0) return { ok: false, files: 0, reason: 'file integrity monitoring is disabled or has no configured paths' };
    await this.ensureAutoCanaries(new Set(this.autoCanaries));
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
      const baseline = await readState(this.opts.baselinePath);
      const previousObserved = await readState(this.opts.observedPath);
      let baselineFilePresent = false;
      if (!baseline) {
        try {
          await lstat(this.opts.baselinePath);
          baselineFilePresent = true;
        } catch (error) {
          baselineFilePresent = (error as NodeJS.ErrnoException).code !== 'ENOENT';
        }
      }
      const canCreate = this.autoCanaries.filter((path) => {
        if (!baseline && !baselineFilePresent) return true;
        return !!baseline && !baseline.targets.includes(path) && !previousObserved?.targets.includes(path);
      });
      await this.ensureAutoCanaries(new Set(canCreate));
      const targets = [...new Set([...this.opts.settings.paths, ...this.opts.settings.canaries, ...this.autoCanaries])];
      const current = await scanTargets(targets, this.canaries);
      if (current.complete) {
        const directories = new Set(current.directories);
        for (const path of Object.keys(current.files)) {
          if (!directories.has(path)) directories.add(dirname(path));
        }
        this.refreshWatchers([...directories]);
      }
      if (!current.complete) {
        this.opts.log(`[file-integrity] scan incomplete; no baseline or change state updated (${current.errorPaths.join(', ') || 'configured scan limits reached'})`);
        return;
      }

      if (!baseline) {
        // A missing state file means first enrollment. A present but unreadable
        // or malformed baseline must never be silently replaced: that would
        // turn tampering into the new expected state.
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

      const observed = previousObserved ?? baseline;
      const sameTargets = (left: string[], right: string[]) => {
        const sortedLeft = [...left].sort();
        const sortedRight = [...right].sort();
        return sortedLeft.length === sortedRight.length && sortedLeft.every((path, index) => path === sortedRight[index]);
      };
      if (!sameTargets(baseline.targets, targets)) {
        const removedCanaries = changedPaths(observed.files, current.files)
          .filter((change) => this.canaries.has(change.path) && observed.targets.includes(change.path));
        if (removedCanaries.length) {
          this.emit('critical', 'A file integrity canary changed or disappeared', 'file-integrity-canary', removedCanaries);
        }
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
      const paths = ordinary.map((change) => change.path);
      const beforeEntropy = meanEntropy(paths, observed.files);
      const afterEntropy = meanEntropy(paths, current.files);
      const entropyRose = beforeEntropy !== null && afterEntropy !== null && afterEntropy - beforeEntropy >= MASS_CHANGE_ENTROPY_RISE_BITS;
      if (ordinary.length >= MASS_CHANGE_COUNT || (ordinary.length >= 10 && entropyRose)) {
        const entropyDetail = entropyRose ? `; mean changed-file entropy rose from ${beforeEntropy?.toFixed(2)} to ${afterEntropy?.toFixed(2)} bits` : '';
        this.emit('critical', `${ordinary.length} monitored files changed in one scan${entropyDetail}`, 'file-integrity-mass-change', ordinary);
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
