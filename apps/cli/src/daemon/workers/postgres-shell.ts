import { readFileSync, readdirSync } from 'node:fs';
import { insertEvent } from '../../core/state.js';
import type { ThreatEvent } from '../../types/events.js';

/**
 * `[postgres_shell]`: Postgres running a shell.
 *
 * 2026-11-20, dev2: an attacker logged into a published Supabase Postgres with
 * a stolen superuser password and ran `COPY ... FROM PROGRAM '<cmd>'`, which
 * executes `/bin/sh -c '<cmd>'` as a child of the backend, inside the
 * container. No login failed and nothing watched processes, so nothing fired.
 *
 * Two independent signals:
 *
 *   - `postgres-shell-exec` (critical): a shell or common LOLBin (sh, bash,
 *     dash, busybox, curl, wget, nc, ncat, python*, perl, base64, or anything
 *     touching /dev/tcp) whose parent chain includes a postgres process. Found
 *     by polling /proc on the host, which sees processes inside containers too.
 *     A command that finishes between two polls can be missed; a reverse shell,
 *     a downloader or a miner cannot.
 *   - `postgres-copy-program` (critical) and `postgres-shell-output` (high):
 *     lines in a Postgres container's log (fed by `[docker_logs]`) that name
 *     `FROM PROGRAM` / `TO PROGRAM`, or that are a shell's own error and
 *     job-control output (`sh: 1: curl: not found`, `Killed`, ...), which
 *     lands in the server log because the child inherits its stderr.
 *
 *   [postgres_shell]
 *   enabled = true          # default on (Linux)
 *   poll_seconds = 3
 *   kill = false            # SIGKILL the spawned process tree (never postgres itself)
 *   allow_cmdline = []      # extra regexes for programs postgres may run (archive_command)
 */

export interface PostgresShellSection {
  enabled?: boolean;
  poll_seconds?: number;
  kill?: boolean;
  allow_cmdline?: string[];
}

export interface PostgresShellSettings {
  enabled: boolean;
  pollMs: number;
  kill: boolean;
  allow: RegExp[];
}

/**
 * What postgres legitimately runs through a shell. Each pattern must match a
 * process's WHOLE command line, and none admits shell metacharacters, so
 * `pgsodium_getkey; curl … | sh` is not allowed by the first one.
 */
export const DEFAULT_ALLOW_CMDLINE = [
  // Supabase's pgsodium reads its root key by running this script at startup.
  String.raw`^(?:\S*/)?(?:ba|da)?sh (?:-c )?(?:\S*/)?pgsodium_getkey(?:\.sh)?$`,
  // WAL archiving/restore through the common tools.
  String.raw`^(?:\S*/)?(?:ba|da)?sh -c (?:\S*/)?(?:wal-g|wal-e|pgbackrest|barman-wal-archive|barman-wal-restore)\s[^;&|\x60$<>()]*$`,
];

export function postgresShellSettings(section?: PostgresShellSection): PostgresShellSettings {
  const poll = Number(section?.poll_seconds);
  const extra = Array.isArray(section?.allow_cmdline) ? section!.allow_cmdline : [];
  const allow: RegExp[] = [];
  for (const src of [...DEFAULT_ALLOW_CMDLINE, ...extra]) {
    if (typeof src !== 'string' || !src) continue;
    try { allow.push(new RegExp(src)); } catch { /* a bad pattern allows nothing */ }
  }
  return {
    enabled: section?.enabled !== false && process.platform === 'linux',
    pollMs: Number.isFinite(poll) && poll >= 1 ? Math.min(poll, 60) * 1000 : 3000,
    kill: section?.kill === true,
    allow,
  };
}

// ─── Process tree matching ───────────────────────────────────────────────────

export interface ProcEntry {
  pid: number;
  ppid: number;
  /** /proc/<pid>/comm: at most 15 characters. */
  comm: string;
  /** Clock ticks since boot; with pid, identifies one process across pid reuse. */
  starttime: number;
  /** argv joined by spaces, read lazily. */
  cmdline?: string;
}

/** `pid (comm) state ppid … starttime(22) …` → the fields we need. comm may hold spaces and parens. */
export function parseProcStat(text: string): Omit<ProcEntry, 'cmdline'> | null {
  const open = text.indexOf('(');
  const close = text.lastIndexOf(')');
  if (open < 0 || close < open) return null;
  const pid = Number(text.slice(0, open).trim());
  const comm = text.slice(open + 1, close);
  const rest = text.slice(close + 2).split(' ');
  // rest[0] is field 3 (state), so field N is rest[N - 3].
  const ppid = Number(rest[1]);
  const starttime = Number(rest[19]);
  if (!Number.isInteger(pid) || !Number.isInteger(ppid)) return null;
  return { pid, ppid, comm, starttime: Number.isFinite(starttime) ? starttime : 0 };
}

const POSTGRES_COMMS = new Set(['postgres', 'postmaster', '.postgres-wrapp', '.postgres-wrapper']);

/** The postgres server or one of its backends (the backend renames argv, never comm). */
export function isPostgresProcess(p: Pick<ProcEntry, 'comm' | 'cmdline'>): boolean {
  if (POSTGRES_COMMS.has(p.comm)) return true;
  const argv0 = (p.cmdline ?? '').split(' ', 1)[0];
  const base = argv0.slice(argv0.lastIndexOf('/') + 1);
  return base === 'postgres' || base === 'postmaster' || base === '.postgres-wrapper';
}

const SHELLS_AND_LOLBINS = new Set([
  'sh', 'bash', 'dash', 'ash', 'zsh', 'ksh', 'busybox',
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'perl', 'base64',
]);

function basenameOf(token: string): string {
  return token.slice(token.lastIndexOf('/') + 1);
}

/**
 * A process postgres has no business starting: a shell or LOLBin by comm or
 * argv[0], any python, `timeout` aimed at /dev/tcp, or anything at all whose
 * command line opens /dev/tcp or /dev/udp.
 */
export function isSuspiciousProgram(p: Pick<ProcEntry, 'comm' | 'cmdline'>): boolean {
  const cmd = p.cmdline ?? '';
  if (/\/dev\/(?:tcp|udp)\//.test(cmd)) return true;
  const names = [p.comm, basenameOf(cmd.split(' ', 1)[0])].filter(Boolean);
  for (const n of names) {
    if (SHELLS_AND_LOLBINS.has(n)) return true;
    if (/^python(?:\d+(?:\.\d+)?)?$/.test(n)) return true;
  }
  return false;
}

export interface PostgresShellHit {
  /** The suspicious process. */
  proc: ProcEntry;
  /** The postgres process it descends from. */
  postgres: ProcEntry;
  /** pid chain from the hit up to (not including) postgres: [hit, parent, …, postgres's direct child]. */
  chain: ProcEntry[];
}

/** What /proc looks like to the matcher; the real one and the test fixtures implement it. */
export interface ProcTable {
  get(pid: number): ProcEntry | undefined;
  /** Loads cmdline on demand (cached by the caller). */
  cmdline(pid: number): string;
}

const MAX_DEPTH = 64;

/**
 * Whether `pid` is a shell/LOLBin descended from postgres, and the chain if so.
 * Null when it is not suspicious, has no postgres ancestor, or a process in
 * the chain is an allowed program (`allow_cmdline`): pgsodium's key script runs
 * bash, and so may an archive_command.
 */
export function matchPostgresShell(pid: number, table: ProcTable, allow: RegExp[] = []): PostgresShellHit | null {
  const self = table.get(pid);
  if (!self || pid <= 1) return null;
  if (isPostgresProcess(self)) return null;
  if (!isSuspiciousProgram(self) && !isSuspiciousProgram({ comm: self.comm, cmdline: table.cmdline(pid) })) return null;

  const chain: ProcEntry[] = [];
  let cur: ProcEntry | undefined = self;
  for (let depth = 0; cur && depth < MAX_DEPTH; depth++) {
    if (isPostgresProcess(cur)) {
      for (const link of chain) {
        const cmd = table.cmdline(link.pid);
        if (allow.some((re) => re.test(cmd))) return null;
      }
      const proc = { ...self, cmdline: table.cmdline(pid) };
      return { proc, postgres: { ...cur, cmdline: table.cmdline(cur.pid) }, chain };
    }
    chain.push(cur);
    if (cur.ppid <= 1 || cur.ppid === cur.pid) return null;
    cur = table.get(cur.ppid);
  }
  return null;
}

// ─── Docker log line patterns ────────────────────────────────────────────────

/** `sh: 1: curl: not found`, `/bin/bash: line 1: …`, `busybox: …`. Postgres's own lines start with its prefix, never this. */
const SHELL_ERROR = /^(?:\S*\/)?(?:sh|bash|dash|ash|busybox)(?:\[\d+\])?:\s/;
/** Job control and signal reports a shell prints for a child: `Killed`, `[1]+  Terminated  cmd`, `Quit (core dumped)`. */
const JOB_CONTROL = /^(?:\[\d+\][+-]?\s+)?(?:Terminated|Killed|Quit \(core dumped\)|Segmentation fault(?: \(core dumped\))?|Hangup)(?:\s|$)/;
const COPY_PROGRAM = /\b(?:FROM|TO)\s+PROGRAM\b/i;

export type PostgresShellLogKind = 'copy_program' | 'shell_output';

/** Which shell signal a Postgres container log line carries, or null. */
export function classifyPostgresShellLine(line: string): PostgresShellLogKind | null {
  if (COPY_PROGRAM.test(line)) return 'copy_program';
  const bare = line.replace(/^\s+/, '');
  if (SHELL_ERROR.test(bare) || JOB_CONTROL.test(bare)) return 'shell_output';
  return null;
}

/** The event for one Postgres container log line, or null when it carries no shell signal. */
export function postgresShellLogEvent(line: string, container: string, now: Date = new Date()): ThreatEvent | null {
  const kind = classifyPostgresShellLine(line);
  if (!kind) return null;
  const copy = kind === 'copy_program';
  return {
    timestamp: now,
    module: 'postgres-shell',
    category: 'system',
    // A shell's error line alone could be the container's own entrypoint
    // script; COPY … PROGRAM is the command execution itself.
    severity: copy ? 'critical' : 'high',
    message: copy
      ? `Postgres ran COPY … PROGRAM (shell command execution) in ${container}`
      : `Shell output in the Postgres log of ${container}: a program run by postgres wrote to its stderr`,
    details: {
      rule_id: copy ? 'postgres-copy-program' : 'postgres-shell-output',
      description: copy
        ? 'COPY FROM/TO PROGRAM runs an OS command as the postgres user. Outside a migration you wrote, that is a superuser credential in the wrong hands.'
        : 'Shell error or job-control output in a Postgres server log means postgres started a shell (COPY FROM PROGRAM, an extension, or archive_command).',
      service: 'postgres',
      container,
      kind,
      line: line.slice(0, 500),
    },
  };
}

/**
 * `postgresShellLogEvent` with a per-container, per-kind cooldown, so an
 * attacker's loop does not page once per line. The first line always fires.
 */
export function shellLogDetector(cooldownMs = 60_000, now: () => number = Date.now): (line: string, container: string) => ThreatEvent | null {
  const last = new Map<string, number>();
  return (line, container) => {
    const event = postgresShellLogEvent(line, container, new Date(now()));
    if (!event) return null;
    const key = `${container}|${event.details?.kind}`;
    const at = now();
    if (at - (last.get(key) ?? -Infinity) < cooldownMs) return null;
    last.set(key, at);
    if (last.size > 1000) last.clear();
    return event;
  };
}

// ─── The /proc poller ────────────────────────────────────────────────────────

export interface ProcFs {
  pids(): number[];
  stat(pid: number): string | null;
  cmdline(pid: number): string | null;
  cgroup(pid: number): string | null;
  kill(pid: number, signal: NodeJS.Signals): void;
}

const realProcFs: ProcFs = {
  pids: () => {
    try { return readdirSync('/proc').filter((n) => /^\d+$/.test(n)).map(Number); } catch { return []; }
  },
  stat: (pid) => { try { return readFileSync(`/proc/${pid}/stat`, 'utf-8'); } catch { return null; } },
  cmdline: (pid) => {
    try { return readFileSync(`/proc/${pid}/cmdline`, 'utf-8').replace(/\0+$/, '').replace(/\0/g, ' '); } catch { return null; }
  },
  cgroup: (pid) => { try { return readFileSync(`/proc/${pid}/cgroup`, 'utf-8'); } catch { return null; } },
  kill: (pid, signal) => { process.kill(pid, signal); },
};

/** The Docker container id in a /proc/<pid>/cgroup, short form, or undefined. */
export function containerIdFromCgroup(text: string | null): string | undefined {
  if (!text) return undefined;
  const m = /(?:docker[-/]|containerd[-/]|cri-containerd-|libpod-)([0-9a-f]{64})/.exec(text);
  return m ? m[1].slice(0, 12) : undefined;
}

export class PostgresShellWatch {
  private timer: NodeJS.Timeout | null = null;
  private fs: ProcFs;
  /** pid:starttime of processes already reported, so one shell alerts once. */
  private alerted = new Set<string>();
  private cmdlines = new Map<string, string>();

  constructor(private opts: {
    bus: { publish(event: ThreatEvent): void };
    settings: PostgresShellSettings;
    log: (line: string) => void;
    /** `[remediation]` dry_run: report the kill instead of doing it. */
    dryRun?: () => boolean;
    procfs?: ProcFs;
  }) {
    this.fs = opts.procfs ?? realProcFs;
  }

  start(): boolean {
    const { settings } = this.opts;
    if (!settings.enabled) return false;
    this.opts.log(`[postgres-shell] watching for shells under postgres every ${settings.pollMs / 1000}s (kill ${settings.kill ? 'ON' : 'off'})`);
    this.poll();
    this.timer = setInterval(() => { try { this.poll(); } catch (err) { this.opts.log(`[postgres-shell] poll failed: ${(err as Error).message}`); } }, settings.pollMs);
    this.timer.unref?.();
    return true;
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** One pass over /proc. Returns the events raised. */
  poll(): ThreatEvent[] {
    const entries = new Map<number, ProcEntry>();
    for (const pid of this.fs.pids()) {
      const text = this.fs.stat(pid);
      const parsed = text ? parseProcStat(text) : null;
      if (parsed) entries.set(pid, parsed);
    }
    const live = new Set<string>();
    for (const e of entries.values()) live.add(`${e.pid}:${e.starttime}`);
    // Forget processes that are gone.
    for (const k of this.alerted) if (!live.has(k)) this.alerted.delete(k);
    for (const k of this.cmdlines.keys()) if (!live.has(k)) this.cmdlines.delete(k);

    const table: ProcTable = {
      get: (pid) => entries.get(pid),
      cmdline: (pid) => {
        const e = entries.get(pid);
        if (!e) return '';
        const key = `${e.pid}:${e.starttime}`;
        let c = this.cmdlines.get(key);
        if (c === undefined) {
          c = this.fs.cmdline(pid) ?? '';
          this.cmdlines.set(key, c);
        }
        return c;
      },
    };

    const out: ThreatEvent[] = [];
    for (const e of entries.values()) {
      const key = `${e.pid}:${e.starttime}`;
      if (this.alerted.has(key)) continue;
      // Cheap prefilter on comm alone; the matcher reads cmdline only for these.
      if (!isSuspiciousProgram(e) && !['timeout', 'env', 'nohup', 'setsid'].includes(e.comm)
        && !/^python/.test(e.comm)) {
        continue;
      }
      const hit = matchPostgresShell(e.pid, table, this.opts.settings.allow);
      if (!hit) continue;
      this.alerted.add(key);
      const event = this.report(hit);
      out.push(event);
    }
    return out;
  }

  private report(hit: PostgresShellHit): ThreatEvent {
    const container = containerIdFromCgroup(this.fs.cgroup(hit.proc.pid));
    // The process postgres started directly: killing its tree ends the command.
    const root = hit.chain[hit.chain.length - 1];
    let killed: number[] = [];
    let killNote: string | undefined;
    if (this.opts.settings.kill) {
      if (this.opts.dryRun?.()) {
        killNote = 'dry_run: not killed';
      } else {
        killed = this.killTree(root.pid);
        killNote = killed.length ? `killed ${killed.join(', ')}` : 'kill failed';
      }
    }
    const cmd = (hit.proc.cmdline || hit.proc.comm).slice(0, 300);
    const event: ThreatEvent = {
      timestamp: new Date(),
      module: 'postgres-shell',
      category: 'system',
      severity: 'critical',
      message: `Postgres executed a shell: ${hit.proc.comm} (pid ${hit.proc.pid}) "${cmd}" under postgres pid ${hit.postgres.pid}${container ? ` in container ${container}` : ''}${killNote ? ` (${killNote})` : ''}`,
      details: {
        rule_id: 'postgres-shell-exec',
        description: 'A shell or download/network tool running as a descendant of postgres means OS command execution through the database (COPY FROM PROGRAM, an untrusted language, or a malicious extension). Rotate the superuser password and close the port.',
        pid: hit.proc.pid,
        comm: hit.proc.comm,
        command: cmd,
        postgres_pid: hit.postgres.pid,
        postgres_cmdline: (hit.postgres.cmdline ?? '').slice(0, 200),
        chain: hit.chain.map((p) => ({ pid: p.pid, comm: p.comm })),
        ...(container ? { container } : {}),
        kill_enabled: this.opts.settings.kill,
        ...(killed.length ? { killed } : {}),
      },
    };
    try { insertEvent(event); } catch { /* db optional */ }
    this.opts.bus.publish(event);
    this.opts.log(`[postgres-shell] ${event.message}`);
    return event;
  }

  /**
   * SIGKILL `rootPid` and every descendant, children first. Never postgres,
   * never pid 1, never ourselves: re-checked against a fresh read of /proc.
   */
  private killTree(rootPid: number): number[] {
    const entries = new Map<number, ProcEntry>();
    for (const pid of this.fs.pids()) {
      const text = this.fs.stat(pid);
      const parsed = text ? parseProcStat(text) : null;
      if (parsed) entries.set(pid, parsed);
    }
    const root = entries.get(rootPid);
    if (!root) return [];
    const children = new Map<number, number[]>();
    for (const e of entries.values()) {
      const list = children.get(e.ppid) ?? [];
      list.push(e.pid);
      children.set(e.ppid, list);
    }
    const order: number[] = [];
    const visit = (pid: number, depth: number) => {
      if (depth > MAX_DEPTH) return;
      for (const c of children.get(pid) ?? []) visit(c, depth + 1);
      order.push(pid);
    };
    visit(rootPid, 0);
    const killed: number[] = [];
    for (const pid of order) {
      const e = entries.get(pid);
      if (!e || pid <= 1 || pid === process.pid || pid === process.ppid) continue;
      if (isPostgresProcess({ comm: e.comm, cmdline: this.fs.cmdline(pid) ?? '' })) continue;
      try { this.fs.kill(pid, 'SIGKILL'); killed.push(pid); } catch { /* gone, or not permitted */ }
    }
    return killed;
  }
}
