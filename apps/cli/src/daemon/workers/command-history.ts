import {
  chmodSync,
  closeSync,
  constants,
  fchownSync,
  fchmodSync,
  fsyncSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';
import { randomUUID } from 'node:crypto';
import type { ThreatEvent } from '../../types/events.js';
import type { CommandHistorySection } from '../../types/config.js';

const POLL_MS = 60_000;
const MAX_HISTORY_BYTES = 4 * 1024 * 1024;
const MAX_COMPRESSED_HISTORY_BYTES = MAX_HISTORY_BYTES + 65_536;
const MAX_SNAPSHOTS = 96;
const SNAPSHOT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
const HISTORY_TARGETS: Record<string, string[]> = {
  bash: ['.bash_history'],
  zsh: ['.zsh_history'],
  fish: ['.local/share/fish/fish_history'],
  ksh: ['.sh_history'],
};

export interface HistoryAccount {
  uid: number;
  gid: number;
  name: string;
  home: string;
  shell: string;
}

export interface CommandHistorySettings { enabled: boolean }

export function commandHistorySettings(section: CommandHistorySection | undefined): CommandHistorySettings {
  // Command histories can contain credentials and private work details. Keep
  // collection opt-in; administrators can enable it explicitly per host.
  return { enabled: section?.enabled === true };
}

export interface CommandHistoryOptions {
  bus: { publish(event: ThreatEvent): void };
  stateDir: string;
  settings: CommandHistorySettings;
  log: (line: string) => void;
  pollMs?: number;
  now?: () => Date;
  listAccounts?: () => HistoryAccount[];
}

export function historyAccounts(): HistoryAccount[] {
  let passwd: string;
  try {
    passwd = execFileSync('getent', ['passwd'], { encoding: 'utf8', timeout: 5_000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    try { passwd = readFileSync('/etc/passwd', 'utf8'); } catch { return []; }
  }

  const root = typeof process.getuid === 'function' && process.getuid() === 0;
  return passwd.split('\n').flatMap((line) => {
    const fields = line.split(':');
    const uid = Number(fields[2]);
    const gid = Number(fields[3]);
    const name = fields[0] ?? '';
    const home = fields[5] ?? '';
    const shell = fields[6] ?? '';
    if (!Number.isInteger(uid) || !Number.isInteger(gid) || !isAbsolute(home) || home === '/' || home.split('/').includes('..')) return [];
    if (root ? uid !== 0 && uid < 1000 : uid !== process.getuid?.()) return [];
    if (!HISTORY_TARGETS[basename(shell)]) return [];
    return [{ uid, gid, name, home, shell }];
  });
}

/** Homes whose history files the systemd service may repair when collection is enabled. */
export function historyWritableHomes(): string[] {
  return [...new Set(historyAccounts().map((account) => account.home))]
    // Whitespace needs systemd-specific escaping. Skipping an unusual path is
    // safer than rendering an ambiguous ReadWritePaths directive.
    .filter((home) => /^\/[A-Za-z0-9._/-]+$/.test(home));
}

function descriptorPath(directoryFd: number, name: string): string {
  return `/proc/self/fd/${directoryFd}/${name}`;
}

/** Walk an absolute path one no-follow directory descriptor at a time. */
function openDirectoryChain(path: string): number {
  if (!isAbsolute(path) || path.split(sep).includes('..')) throw new Error('directory path is not a safe absolute path');
  const flags = constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0);
  let fd = openSync('/', flags);
  try {
    for (const part of path.split(sep).filter((item) => item && item !== '.')) {
      const next = openSync(descriptorPath(fd, part), flags);
      closeSync(fd);
      fd = next;
    }
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function readExact(fd: number, size: number): Buffer | null {
  const data = Buffer.alloc(size);
  let offset = 0;
  while (offset < data.length) {
    const read = readSync(fd, data, offset, data.length - offset, offset);
    if (read === 0) break;
    offset += read;
  }
  return offset === data.length ? data : null;
}

function privateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('history storage path is not a directory');
  chmodSync(path, 0o700);
}

function safeReadHistory(directoryFd: number, name: string, uid: number): Buffer | null {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const fd = openSync(descriptorPath(directoryFd, name), constants.O_RDONLY | noFollow);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.uid !== uid) return null;
    if (opened.size > MAX_HISTORY_BYTES) throw new Error(`history file exceeds ${MAX_HISTORY_BYTES} bytes`);
    const data = readExact(fd, opened.size);
    if (data === null) return null;
    const after = fstatSync(fd);
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) return null;
    return data;
  } finally {
    closeSync(fd);
  }
}

function atomicWrite(path: string, data: Buffer, mode = 0o600, owner?: { uid: number; gid: number }, parentFd?: number): void {
  const dirFd = parentFd ?? openDirectoryChain(dirname(path));
  const ownsDirFd = parentFd === undefined;
  const name = basename(path);
  const temp = descriptorPath(dirFd, `${name}.${randomUUID()}.tmp`);
  const destination = descriptorPath(dirFd, name);
  const noFollow = constants.O_NOFOLLOW ?? 0;
  let fd: number | undefined;
  try {
    fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow, mode);
    let offset = 0;
    while (offset < data.length) offset += writeSync(fd, data, offset, data.length - offset);
    // Set mode while the file is still owned by the daemon. The systemd unit
    // intentionally omits CAP_FOWNER; after fchown to a user, root cannot
    // fchmod that user's file without that extra capability.
    fchmodSync(fd, mode);
    if (owner && typeof process.getuid === 'function' && process.getuid() === 0) {
      fchownSync(fd, owner.uid, owner.gid);
    }
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, destination);
  } catch (error) {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* best effort */ }
    }
    try { unlinkSync(temp); } catch { /* best effort */ }
    throw error;
  } finally {
    if (ownsDirFd) closeSync(dirFd);
  }
}

function readCurrentBackup(path: string): Buffer | null {
  let fd: number | undefined;
  try {
    const parentFd = openDirectoryChain(dirname(path));
    try {
      fd = openSync(descriptorPath(parentFd, basename(path)), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    } finally {
      closeSync(parentFd);
    }
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_COMPRESSED_HISTORY_BYTES) return null;
    const compressed = readExact(fd, stat.size);
    const after = fstatSync(fd);
    if (!compressed || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs) return null;
    return gunzipSync(compressed, { maxOutputLength: MAX_HISTORY_BYTES });
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function compactTime(date: Date): string {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1Z');
}

export class CommandHistoryWatcher {
  private timer: NodeJS.Timeout | null = null;
  private scanning = false;
  private readonly pollMs: number;
  private readonly now: () => Date;
  private readonly listAccounts: () => HistoryAccount[];
  private readonly root: string;

  constructor(private readonly opts: CommandHistoryOptions) {
    this.pollMs = Math.max(10_000, opts.pollMs ?? POLL_MS);
    this.now = opts.now ?? (() => new Date());
    this.listAccounts = opts.listAccounts ?? historyAccounts;
    this.root = join(opts.stateDir, 'command-history');
  }

  start(): void {
    if (!this.opts.settings.enabled) {
      this.opts.log('[command-history] disabled; set [command_history] enabled = true to collect local shell history');
      return;
    }
    if (process.platform !== 'linux') {
      this.opts.log('[command-history] unavailable: only Linux account history paths are supported');
      return;
    }
    try {
      privateDirectory(this.root);
    } catch (error) {
      this.opts.log(`[command-history] cannot create private storage: ${(error as Error).message}`);
      return;
    }
    this.opts.log(`[command-history] enabled; private snapshots under ${this.root}, checking every ${Math.round(this.pollMs / 1000)}s`);
    void this.scanOnce();
    this.timer = setInterval(() => { void this.scanOnce(); }, this.pollMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async scanOnce(): Promise<void> {
    if (this.scanning || !this.opts.settings.enabled || process.platform !== 'linux') return;
    this.scanning = true;
    try {
      privateDirectory(this.root);
      for (const account of this.listAccounts()) {
        if (!Number.isInteger(account.uid) || account.uid < 0 || !isAbsolute(account.home)) continue;
        const targets = this.targetsFor(account);
        for (const relative of targets) this.scanFile(account, relative);
      }
    } catch (error) {
      this.opts.log(`[command-history] scan failed: ${(error as Error).message}`);
    } finally {
      this.scanning = false;
    }
  }

  private targetsFor(account: HistoryAccount): string[] {
    const targets = new Set(HISTORY_TARGETS[basename(account.shell)] ?? []);
    for (const relative of Object.values(HISTORY_TARGETS).flat()) {
      if (targets.has(relative)) continue;
      const path = join(account.home, relative);
      try {
        // lstat includes a history file that has been redirected to /dev/null.
        lstatSync(path);
        targets.add(relative);
        continue;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') continue;
      }

      const current = join(this.root, String(account.uid), `${basename(relative)}.current.gz`);
      if (readCurrentBackup(current) !== null) targets.add(relative);
    }
    return [...targets];
  }

  private scanFile(account: HistoryAccount, relative: string): void {
    const path = join(account.home, relative);
    const store = join(this.root, String(account.uid), basename(relative));
    const current = `${store}.current.gz`;
    let userParentFd: number;
    try {
      userParentFd = openDirectoryChain(dirname(path));
    } catch {
      this.opts.log(`[command-history] skipped uid=${account.uid} ${basename(relative)} because its parent path is missing or not a real directory`);
      return;
    }

    try {
      privateDirectory(dirname(store));
      const userPath = descriptorPath(userParentFd, basename(path));
      let status;
      try { status = lstatSync(userPath); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }

      const backup = readCurrentBackup(current);
      const suspicious = status && (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1 || status.uid !== account.uid);
      const missingWithBackup = !status && backup !== null;
      if (suspicious || missingWithBackup) {
        const reason = !status ? 'deleted' : status.isSymbolicLink() ? 'symlinked' : !status.isFile() ? 'not a regular file' : status.nlink !== 1 ? 'hard-linked' : 'owned by another account';
        const restored = backup ?? Buffer.alloc(0);
        this.restore(path, restored, account, userParentFd);
        this.emitTamper(account, relative, reason, backup !== null);
      } else if (!status) {
        // Establish a safe empty file so a later deletion or link becomes visible.
        this.restore(path, Buffer.alloc(0), account, userParentFd);
      }

      const data = safeReadHistory(userParentFd, basename(path), account.uid);
      if (data === null) return;
      const previous = backup;
      if (previous?.equals(data)) {
        this.pruneSnapshots(current);
        return;
      }

      const compressed = gzipSync(data, { level: 6 });
      const stamp = compactTime(this.now());
      atomicWrite(`${store}.${stamp}-${randomUUID().slice(0, 8)}.gz`, compressed);
      atomicWrite(current, compressed);
      this.pruneSnapshots(store);
    } catch (error) {
      this.opts.log(`[command-history] could not snapshot uid=${account.uid} ${basename(relative)}: ${(error as Error).message}`);
    } finally {
      closeSync(userParentFd);
    }
  }

  private restore(path: string, content: Buffer, account: HistoryAccount, parentFd: number): void {
    // Atomic rename replaces a symlink itself and never follows its target.
    atomicWrite(path, content, 0o600, account, parentFd);
  }

  private emitTamper(account: HistoryAccount, relative: string, reason: string, hadBackup: boolean): void {
    const name = /^[A-Za-z0-9_.-]{1,64}$/.test(account.name) ? account.name : `uid ${account.uid}`;
    const event: ThreatEvent = {
      timestamp: this.now(),
      module: 'command-history',
      category: 'system',
      severity: 'medium',
      message: `Shell history for ${name} (${basename(relative)}) was ${reason}; restored${hadBackup ? ' from the latest backup' : ' as an empty file'}`,
      details: { uid: account.uid, account: name, history_file: basename(relative), action: 'restored', reason, had_backup: hadBackup },
    };
    this.opts.bus.publish(event);
    this.opts.log(`[command-history] ${event.message}`);
  }

  private pruneSnapshots(current: string): void {
    const dir = dirname(current);
    const prefix = `${basename(current).replace(/\.current\.gz$/, '')}.`;
    const snapshots = readdirSync(dir)
      .filter((name) => name !== basename(current) && name.startsWith(prefix) && name.endsWith('.gz'))
      .map((name) => ({ path: join(dir, name), name, time: lstatSync(join(dir, name)).mtimeMs }))
      .sort((a, b) => a.time - b.time);
    const cutoff = this.now().getTime() - SNAPSHOT_RETENTION_MS;
    const removeCount = Math.max(0, snapshots.length - MAX_SNAPSHOTS);
    snapshots.forEach((snapshot, index) => {
      if (snapshot.time < cutoff || index < removeCount) {
        try { unlinkSync(snapshot.path); } catch { /* next scan retries */ }
      }
    });
  }
}
