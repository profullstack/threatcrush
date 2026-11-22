/**
 * Opt-in containment of the process writing to a canary or mass-modifying
 * monitored files (`[file_integrity] contain_writer`, issue #308).
 *
 * inotify reports what changed, never who changed it, so the writer is found
 * the slow way: walk /proc/<pid>/fd and keep processes that hold a changed file
 * (or, failing that, a file inside an affected directory) open for WRITING, as
 * read from /proc/<pid>/fdinfo. That is best effort. A writer that already
 * closed its files is invisible, and the walk is capped in processes, file
 * descriptors and wall time. When the walk is incomplete, finds more candidates
 * than configured, or finds nobody, the alert goes out and nothing is signalled.
 *
 * SIGSTOP is the recommended mode: it freezes the writer while an operator
 * looks, and `kill -CONT <pid>` undoes it. SIGKILL only when chosen explicitly.
 *
 * Reading another user's /proc/<pid>/fd needs CAP_SYS_PTRACE; `threatcrush
 * install-service` adds it to the unit only when contain_writer is enabled.
 */
import { readdir, readFile, readlink } from 'node:fs/promises';
import { basename, dirname } from 'node:path';

export type ContainWriterMode = 'off' | 'stop' | 'kill';

export interface WriterContainmentSettings {
  mode: ContainWriterMode;
  /** More unprotected writers than this is ambiguous: alert only. */
  maxProcesses: number;
  /** Executables never signalled. An entry ending in `/` covers a directory. */
  neverContain: string[];
}

/** What the containment code needs from /proc; tests inject a fake. */
export interface WriterProcFs {
  pids(): Promise<number[]> | number[];
  /** Raw /proc/<pid>/stat, or null when the process is gone or unreadable. */
  stat(pid: number): Promise<string | null> | string | null;
  /** readlink /proc/<pid>/exe, or null (kernel thread, gone, no permission). */
  exe(pid: number): Promise<string | null> | string | null;
  /** fd numbers under /proc/<pid>/fd, or null when unreadable. */
  fds(pid: number): Promise<string[] | null> | string[] | null;
  /** readlink /proc/<pid>/fd/<fd>. */
  fdTarget(pid: number, fd: string): Promise<string | null> | string | null;
  /** The `flags:` field of /proc/<pid>/fdinfo/<fd>, parsed from octal. */
  fdFlags(pid: number, fd: string): Promise<number | null> | number | null;
  kill(pid: number, signal: NodeJS.Signals): void;
}

export const realWriterProcFs: WriterProcFs = {
  async pids() {
    try { return (await readdir('/proc')).filter((name) => /^\d+$/.test(name)).map(Number); } catch { return []; }
  },
  async stat(pid) {
    try { return await readFile(`/proc/${pid}/stat`, 'utf8'); } catch { return null; }
  },
  async exe(pid) {
    try { return await readlink(`/proc/${pid}/exe`); } catch { return null; }
  },
  async fds(pid) {
    try { return await readdir(`/proc/${pid}/fd`); } catch { return null; }
  },
  async fdTarget(pid, fd) {
    try { return await readlink(`/proc/${pid}/fd/${fd}`); } catch { return null; }
  },
  async fdFlags(pid, fd) {
    try {
      const match = /^flags:\s*([0-7]+)$/m.exec(await readFile(`/proc/${pid}/fdinfo/${fd}`, 'utf8'));
      return match ? Number.parseInt(match[1], 8) : null;
    } catch { return null; }
  },
  kill(pid, signal) { process.kill(pid, signal); },
};

export const CONTAIN_DEFAULT_MAX_PROCESSES = 3;
const MAX_PIDS = 8192;
const MAX_FDS_PER_PROCESS = 4096;
const MAX_MATCH_FILES = 1000;
const MAX_MATCH_DIRECTORIES = 64;
const MAX_REPORTED_FILES = 10;
const DEFAULT_BUDGET_MS = 1500;
const O_ACCMODE = 0o3;

export function containWriterSettings(section: {
  contain_writer?: unknown;
  contain_max_processes?: unknown;
  never_contain?: unknown;
} | undefined): WriterContainmentSettings {
  const raw = section?.contain_writer;
  const mode: ContainWriterMode = raw === 'stop' || raw === 'kill' ? raw : 'off';
  const max = section?.contain_max_processes;
  const maxProcesses = typeof max === 'number' && Number.isFinite(max)
    ? Math.max(1, Math.min(20, Math.floor(max)))
    : CONTAIN_DEFAULT_MAX_PROCESSES;
  const neverContain = Array.isArray(section?.never_contain)
    ? section.never_contain.filter((value): value is string => typeof value === 'string' && value.startsWith('/'))
    : [];
  return { mode, maxProcesses, neverContain };
}

export interface ContainedProcess {
  pid: number;
  comm: string;
  exe: string;
  /** Changed or in-directory files it held open for writing (first few). */
  files: string[];
  signal?: 'SIGSTOP' | 'SIGKILL';
  result?: 'sent' | 'failed' | 'dry-run' | 'gone';
  error?: string;
}

export interface ContainmentReport {
  mode: ContainWriterMode;
  /**
   * contained: a signal was sent to every candidate. alert-only: candidates
   * found but not acted on (see reason). no-writer: nobody holds the files.
   */
  action: 'contained' | 'partial' | 'alert-only' | 'dry-run' | 'no-writer';
  reason?: string;
  /** exact: a process held a changed file. directory: matched by directory. */
  match?: 'exact' | 'directory';
  processes: ContainedProcess[];
  /** Writers that are never signalled (pid 1, ourselves, sshd, systemd*, never_contain). */
  protected_writers: Array<{ pid: number; comm: string; exe: string }>;
  incomplete: boolean;
}

interface ProcInfo { pid: number; ppid: number; comm: string; starttime: number }

function parseStat(text: string): ProcInfo | null {
  const open = text.indexOf('(');
  const close = text.lastIndexOf(')');
  if (open < 0 || close < open) return null;
  const pid = Number(text.slice(0, open).trim());
  const rest = text.slice(close + 2).split(' ');
  const ppid = Number(rest[1]);
  const starttime = Number(rest[19]);
  if (!Number.isInteger(pid) || !Number.isInteger(ppid)) return null;
  return { pid, ppid, comm: text.slice(open + 1, close), starttime: Number.isFinite(starttime) ? starttime : 0 };
}

const stripDeleted = (path: string) => path.replace(/ \(deleted\)$/, '');

export interface WriterContainmentOptions {
  settings: WriterContainmentSettings;
  log: (line: string) => void;
  procfs?: WriterProcFs;
  /** `[remediation] dry_run`: report the signal instead of sending it. */
  dryRun?: () => boolean;
  /** The daemon's own pid and parent; overridable for tests. */
  selfPid?: number;
  parentPid?: number;
  platform?: NodeJS.Platform;
  nowMs?: () => number;
  budgetMs?: number;
}

export class WriterContainment {
  private readonly fs: WriterProcFs;
  private readonly selfPid: number;
  private readonly parentPid: number;
  private readonly nowMs: () => number;

  constructor(private readonly opts: WriterContainmentOptions) {
    this.fs = opts.procfs ?? realWriterProcFs;
    this.selfPid = opts.selfPid ?? process.pid;
    this.parentPid = opts.parentPid ?? process.ppid;
    this.nowMs = opts.nowMs ?? Date.now;
  }

  get enabled(): boolean {
    return this.opts.settings.mode !== 'off' && (this.opts.platform ?? process.platform) === 'linux';
  }

  /** A process that must never be signalled, whatever it wrote. */
  isProtected(info: ProcInfo, exe: string): boolean {
    if (info.pid <= 2 || info.ppid === 2) return true; // init, kthreadd, kernel threads
    if (info.pid === this.selfPid || info.pid === this.parentPid) return true;
    const path = stripDeleted(exe);
    const names = [info.comm, basename(path)];
    if (names.some((name) => name === 'sshd' || name.startsWith('sshd-') || name.startsWith('systemd'))) return true;
    return this.opts.settings.neverContain.some((entry) => entry.endsWith('/') ? path.startsWith(entry) : path === entry);
  }

  /**
   * Find who holds `files` (or files under their directories) open for writing,
   * and signal them when attribution is unambiguous.
   */
  async contain(files: string[], extraDirectories: string[] = []): Promise<ContainmentReport> {
    const { mode, maxProcesses } = this.opts.settings;
    const report: ContainmentReport = { mode, action: 'no-writer', processes: [], protected_writers: [], incomplete: false };
    if (!this.enabled) {
      report.action = 'alert-only';
      report.reason = mode === 'off' ? 'contain_writer is off' : 'writer containment needs Linux /proc';
      return report;
    }

    const exact = new Set(files.slice(0, MAX_MATCH_FILES));
    const directories = [...new Set([...files.map((file) => dirname(file)), ...extraDirectories])]
      .filter((dir) => dir !== '/')
      .slice(0, MAX_MATCH_DIRECTORIES)
      .map((dir) => (dir.endsWith('/') ? dir : `${dir}/`));
    if (files.length > MAX_MATCH_FILES) report.incomplete = true;

    const deadline = this.nowMs() + (this.opts.budgetMs ?? DEFAULT_BUDGET_MS);
    const exactHits = new Map<number, { info: ProcInfo; exe: string; files: string[] }>();
    const dirHits = new Map<number, { info: ProcInfo; exe: string; files: string[] }>();

    let pids = await this.fs.pids();
    if (pids.length > MAX_PIDS) { report.incomplete = true; pids = pids.slice(0, MAX_PIDS); }
    for (const pid of pids) {
      if (this.nowMs() > deadline) { report.incomplete = true; break; }
      const fds = await this.fs.fds(pid);
      if (!fds || fds.length === 0) continue;
      let exactFiles: string[] = [];
      let dirFiles: string[] = [];
      for (const fd of fds.slice(0, MAX_FDS_PER_PROCESS)) {
        const raw = await this.fs.fdTarget(pid, fd);
        if (!raw || !raw.startsWith('/')) continue;
        const target = stripDeleted(raw);
        const isExact = exact.has(target);
        const inDir = !isExact && directories.some((dir) => target.startsWith(dir));
        if (!isExact && !inDir) continue;
        const flags = await this.fs.fdFlags(pid, fd);
        if (flags === null || (flags & O_ACCMODE) === 0) continue; // read-only
        if (isExact) exactFiles.push(target); else dirFiles.push(target);
      }
      if (fds.length > MAX_FDS_PER_PROCESS) report.incomplete = true;
      if (exactFiles.length === 0 && dirFiles.length === 0) continue;
      const statText = await this.fs.stat(pid);
      const info = statText ? parseStat(statText) : null;
      if (!info) continue;
      const exe = (await this.fs.exe(pid)) ?? '';
      exactFiles = [...new Set(exactFiles)];
      dirFiles = [...new Set(dirFiles)];
      if (!exe || this.isProtected(info, exe)) {
        report.protected_writers.push({ pid, comm: info.comm, exe: exe || '[kernel]' });
        continue;
      }
      if (exactFiles.length) exactHits.set(pid, { info, exe, files: [...exactFiles, ...dirFiles] });
      else dirHits.set(pid, { info, exe, files: dirFiles });
    }

    // The process holding the changed file itself is the strongest evidence;
    // fall back to "writing inside the same directory" only when nobody does.
    const chosen = exactHits.size ? exactHits : dirHits;
    report.match = exactHits.size ? 'exact' : dirHits.size ? 'directory' : undefined;
    report.processes = [...chosen.values()].map(({ info, exe, files: held }) => ({
      pid: info.pid,
      comm: info.comm,
      exe: stripDeleted(exe),
      files: held.slice(0, MAX_REPORTED_FILES),
    }));
    if (report.processes.length === 0) {
      report.action = 'no-writer';
      report.reason = report.incomplete
        ? 'no writer found before the /proc walk limit; it may have closed its files'
        : 'no process holds the changed files open for writing; it may have closed them';
      if (!report.match) delete report.match;
      return report;
    }
    if (report.incomplete) {
      report.action = 'alert-only';
      report.reason = 'the /proc walk hit a limit, so attribution may be incomplete';
      return report;
    }
    if (report.processes.length > maxProcesses) {
      report.action = 'alert-only';
      report.reason = `${report.processes.length} candidate writers exceeds contain_max_processes (${maxProcesses})`;
      return report;
    }

    const signal: 'SIGSTOP' | 'SIGKILL' = mode === 'kill' ? 'SIGKILL' : 'SIGSTOP';
    const dryRun = this.opts.dryRun?.() === true;
    let sent = 0;
    for (const proc of report.processes) {
      proc.signal = signal;
      // Re-read stat right before signalling so a recycled pid is never hit.
      const before = chosen.get(proc.pid)!.info;
      const fresh = await this.fs.stat(proc.pid);
      const now = fresh ? parseStat(fresh) : null;
      if (!now || now.starttime !== before.starttime) { proc.result = 'gone'; continue; }
      if (dryRun) { proc.result = 'dry-run'; continue; }
      try {
        this.fs.kill(proc.pid, signal);
        proc.result = 'sent';
        sent++;
      } catch (error) {
        proc.result = 'failed';
        proc.error = (error as Error).message.split('\n')[0].slice(0, 200);
      }
    }
    report.action = dryRun ? 'dry-run' : sent === report.processes.length ? 'contained' : sent > 0 ? 'partial' : 'alert-only';
    if (report.action === 'alert-only') report.reason = 'signal not delivered';
    for (const proc of report.processes) {
      this.opts.log(`[file-integrity] contain_writer=${mode}: ${proc.result} ${signal} to pid ${proc.pid} (${proc.exe}) writing ${proc.files.slice(0, 3).join(', ')}${proc.error ? `: ${proc.error}` : ''}${signal === 'SIGSTOP' && proc.result === 'sent' ? `; resume with kill -CONT ${proc.pid} or end with kill -KILL ${proc.pid}` : ''}`);
    }
    return report;
  }
}

/** One line for an alert message. */
export function summarizeContainment(report: ContainmentReport): string {
  const procs = report.processes.map((p) => `pid ${p.pid} (${basename(p.exe) || p.comm})`).join(', ');
  switch (report.action) {
    case 'contained': return `writer ${procs} ${report.mode === 'kill' ? 'killed (SIGKILL)' : 'stopped (SIGSTOP)'}`;
    case 'partial': return `writer containment partial: ${report.processes.map((p) => `pid ${p.pid} ${p.result}`).join(', ')}`;
    case 'dry-run': return `dry_run: would ${report.mode === 'kill' ? 'SIGKILL' : 'SIGSTOP'} ${procs}`;
    case 'alert-only': return procs ? `writer ${procs} not contained: ${report.reason}` : `writer not contained: ${report.reason}`;
    case 'no-writer': return 'writer not identified';
  }
}
