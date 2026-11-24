import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { accessSync, constants, existsSync } from 'node:fs';
import { isIP } from 'node:net';
import { delimiter, join } from 'node:path';

/**
 * Optional eBPF event source for `[edr]`, driven through the `bpftrace` CLI so
 * ThreatCrush needs no native npm dependency. bpftrace runs with `-f json`,
 * which wraps every printf in a JSON object with a properly escaped `data`
 * string, so a newline in a file name can never split or forge a record.
 *
 * Inside `data`, fields are tab-separated and the one caller-controlled string
 * (the exec file name, or the connecting task's comm) is always the LAST field:
 * the parser splits only the fixed numeric prefix, so a tab inside that string
 * cannot shift the other fields. argv is deliberately not traced: the auditd
 * path discards command arguments, and the eBPF path keeps the same privacy
 * contract (comm after exec is the kernel's basename of the file name anyway).
 *
 * With `peers` on, a connect record also carries the remote address and port
 * (kind `connectp`). The address is there for one purpose: the daemon looks it
 * up in the threat feeds in memory and drops it unless it is listed.
 */

export type EdrSourceSetting = 'auto' | 'auditd' | 'ebpf';
export type EdrSourceKind = 'auditd' | 'ebpf';

export const BPFTRACE_RECORD_TAG = 'TC1';
export const BTF_VMLINUX_PATH = '/sys/kernel/btf/vmlinux';

/** Linux TCP states used by tracepoint:sock:inet_sock_set_state. */
const TCP_SYN_SENT = 2;
const TCP_LISTEN = 10;
const IPPROTO_TCP = 6;
const AF_INET = 2;
const AF_INET6 = 10;

/**
 * The embedded bpftrace program. sched_process_exec fires after a successful
 * exec, so `curtask` already carries the new credentials (setuid applied) and
 * `args.filename` is the path the kernel resolved the binary from. TCP
 * SYN_SENT / LISTEN transitions happen in the connect()/listen() caller's
 * context, so pid/comm identify the process. Requires kernel BTF for
 * `curtask->...` field access.
 */
export function bpftraceScript(opts: { network: boolean; peers?: boolean }): string {
  const prefix = `"${BPFTRACE_RECORD_TAG}\\t%s\\t%d\\t%d\\t%d\\t%s\\n"`;
  // connectp: the remote address and port sit before comm, which stays last.
  const peerPrefix = `"${BPFTRACE_RECORD_TAG}\\t%s\\t%d\\t%d\\t%d\\t%s\\t%d\\t%s\\n"`;
  const lines = [
    'tracepoint:sched:sched_process_exec',
    '{',
    `  printf(${prefix}, "exec", pid, curtask->real_parent->tgid, curtask->cred->euid.val, str(args.filename));`,
    '}',
  ];
  if (opts.network) {
    if (opts.peers) {
      lines.push(
        'tracepoint:sock:inet_sock_set_state',
        `/args.protocol == ${IPPROTO_TCP} && args.newstate == ${TCP_SYN_SENT} && args.family == ${AF_INET}/`,
        '{',
        `  printf(${peerPrefix}, "connectp", pid, curtask->real_parent->tgid, curtask->cred->euid.val, ntop(args.daddr), args.dport, comm);`,
        '}',
        'tracepoint:sock:inet_sock_set_state',
        `/args.protocol == ${IPPROTO_TCP} && args.newstate == ${TCP_SYN_SENT} && args.family == ${AF_INET6}/`,
        '{',
        `  printf(${peerPrefix}, "connectp", pid, curtask->real_parent->tgid, curtask->cred->euid.val, ntop(args.daddr_v6), args.dport, comm);`,
        '}',
      );
    } else {
      lines.push(
        'tracepoint:sock:inet_sock_set_state',
        `/args.protocol == ${IPPROTO_TCP} && args.newstate == ${TCP_SYN_SENT}/`,
        '{',
        `  printf(${prefix}, "connect", pid, curtask->real_parent->tgid, curtask->cred->euid.val, comm);`,
        '}',
      );
    }
    lines.push(
      'tracepoint:sock:inet_sock_set_state',
      `/args.protocol == ${IPPROTO_TCP} && args.newstate == ${TCP_LISTEN}/`,
      '{',
      `  printf(${prefix}, "listen", pid, curtask->real_parent->tgid, curtask->cred->euid.val, comm);`,
      '}',
    );
  }
  return `${lines.join('\n')}\n`;
}

/** argv for spawning bpftrace (never through a shell). */
export function bpftraceArgs(opts: { network: boolean; peers?: boolean }): string[] {
  return ['-q', '-B', 'line', '-f', 'json', '-e', bpftraceScript(opts)];
}

export interface EbpfProcessEvent {
  kind: 'exec' | 'connect' | 'listen';
  pid: number;
  ppid: number;
  euid: number;
  /** exec only: the file name passed to the kernel (may be relative). */
  filename?: string;
  /** connect/listen: task comm; exec: kernel basename of filename (max 15 bytes). */
  comm: string;
  /** connect with `peers` on: the remote address (v4-mapped v6 unwrapped) and port. */
  peerIp?: string;
  peerPort?: number;
}

export type BpftraceLine =
  | { type: 'event'; event: EbpfProcessEvent }
  | { type: 'attached'; probes: number }
  | { type: 'lost'; count: number }
  | { type: 'error'; message: string }
  | null;

const MAX_FIELD = 4096;

function parseRecordText(text: string): EbpfProcessEvent | null {
  const body = text.endsWith('\n') ? text.slice(0, -1) : text;
  const parts: string[] = [];
  let rest = body;
  // Split exactly five fixed fields; everything after the fifth tab is the string field.
  for (let i = 0; i < 5; i++) {
    const at = rest.indexOf('\t');
    if (at < 0) return null;
    parts.push(rest.slice(0, at));
    rest = rest.slice(at + 1);
  }
  const [tag, kind, pidText, ppidText, euidText] = parts;
  if (tag !== BPFTRACE_RECORD_TAG) return null;
  if (kind !== 'exec' && kind !== 'connect' && kind !== 'connectp' && kind !== 'listen') return null;
  const pid = Number(pidText);
  const ppid = Number(ppidText);
  const euid = Number(euidText);
  if (!/^\d+$/.test(pidText) || !/^\d+$/.test(ppidText) || !/^\d+$/.test(euidText)) return null;
  if (!Number.isSafeInteger(pid) || pid <= 0 || !Number.isSafeInteger(ppid) || !Number.isSafeInteger(euid)) return null;
  if (kind === 'connectp') {
    // Two more fixed fields (address, port) precede comm.
    const addrEnd = rest.indexOf('\t');
    const portEnd = addrEnd < 0 ? -1 : rest.indexOf('\t', addrEnd + 1);
    if (portEnd < 0) return null;
    const peerIp = rest.slice(0, addrEnd).replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '');
    const portText = rest.slice(addrEnd + 1, portEnd);
    const comm = rest.slice(portEnd + 1, portEnd + 1 + MAX_FIELD);
    if (!isIP(peerIp) || !/^\d{1,5}$/.test(portText) || Number(portText) > 65535 || !comm) return null;
    return { kind: 'connect', pid, ppid, euid, comm: comm.slice(0, 64), peerIp, peerPort: Number(portText) };
  }
  const value = rest.slice(0, MAX_FIELD);
  if (!value) return null;
  if (kind === 'exec') {
    const base = value.slice(value.lastIndexOf('/') + 1).slice(0, 15);
    return { kind, pid, ppid, euid, filename: value, comm: base || value.slice(0, 15) };
  }
  return { kind, pid, ppid, euid, comm: value.slice(0, 64) };
}

/**
 * Parse one stdout line from `bpftrace -f json`. Plain text lines (bpftrace
 * run without `-f json`) are accepted too, which keeps fixtures readable.
 */
export function parseBpftraceLine(line: string): BpftraceLine {
  const trimmed = line.replace(/\r$/, '');
  if (!trimmed) return null;
  if (trimmed.startsWith('{')) {
    let parsed: unknown;
    try { parsed = JSON.parse(trimmed); } catch { return null; }
    if (!parsed || typeof parsed !== 'object') return null;
    const { type, data } = parsed as { type?: unknown; data?: unknown };
    if (type === 'printf' && typeof data === 'string') {
      const event = parseRecordText(data);
      return event ? { type: 'event', event } : null;
    }
    if (type === 'attached_probes') {
      const probes = Number((data as { probes?: unknown } | null)?.probes);
      return { type: 'attached', probes: Number.isFinite(probes) ? probes : 0 };
    }
    if (type === 'lost_events') {
      const count = Number((data as { events?: unknown } | null)?.events);
      return { type: 'lost', count: Number.isFinite(count) ? count : 0 };
    }
    if (type === 'error' || type === 'warning') {
      return { type: 'error', message: typeof data === 'string' ? data.slice(0, 400) : JSON.stringify(data).slice(0, 400) };
    }
    return null;
  }
  const event = parseRecordText(trimmed);
  return event ? { type: 'event', event } : null;
}

export interface SourceProbe {
  configured: EdrSourceSetting;
  bpftracePath: string | null;
  btfPresent: boolean;
  isRoot: boolean;
  platform?: NodeJS.Platform;
}

export interface SourceSelection {
  source: EdrSourceKind;
  /** True when "ebpf" was requested explicitly but the host cannot run it. */
  degraded: boolean;
  reason: string;
}

/** Decide which event source to use. Pure; the probe gathers host facts. */
export function selectEdrSource(probe: SourceProbe): SourceSelection {
  if (probe.configured === 'auditd') return { source: 'auditd', degraded: false, reason: 'source = "auditd" configured' };
  const missing: string[] = [];
  if ((probe.platform ?? 'linux') !== 'linux') missing.push('not Linux');
  if (!probe.bpftracePath) missing.push('bpftrace not installed');
  if (!probe.btfPresent) missing.push(`kernel BTF (${BTF_VMLINUX_PATH}) missing`);
  if (!probe.isRoot) missing.push('daemon not running as root');
  if (missing.length === 0) {
    return { source: 'ebpf', degraded: false, reason: `bpftrace at ${probe.bpftracePath} with kernel BTF, running as root` };
  }
  return {
    source: 'auditd',
    degraded: probe.configured === 'ebpf',
    reason: `eBPF unavailable (${missing.join('; ')}); using auditd`,
  };
}

const BPFTRACE_DIRS = ['/usr/sbin', '/usr/bin', '/sbin', '/bin', '/usr/local/sbin', '/usr/local/bin', '/snap/bin'];

/** Locate an executable bpftrace in standard system directories (daemon PATH can be minimal). */
export function findBpftrace(env: NodeJS.ProcessEnv = process.env): string | null {
  const dirs = [...BPFTRACE_DIRS, ...(env.PATH ?? '').split(delimiter).filter((dir) => dir.startsWith('/'))];
  for (const dir of new Set(dirs)) {
    const candidate = join(dir, 'bpftrace');
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch { /* keep looking */ }
  }
  return null;
}

export function probeHost(configured: EdrSourceSetting): SourceProbe {
  return {
    configured,
    bpftracePath: configured === 'auditd' ? null : findBpftrace(),
    btfPresent: existsSync(BTF_VMLINUX_PATH),
    isRoot: typeof process.getuid === 'function' && process.getuid() === 0,
    platform: process.platform,
  };
}

type SpawnFn = (command: string, args: string[], options: SpawnOptions) => ChildProcess;

export interface BpftraceSourceOptions {
  bpftracePath: string;
  network: boolean;
  /** Trace the remote address of each connect, for threat-feed matching. */
  peers?: boolean;
  onEvent: (event: EbpfProcessEvent) => void;
  /** Called once when bpftrace cannot be kept running; the caller falls back to auditd. */
  onFatal: (reason: string) => void;
  log: (line: string) => void;
  spawn?: SpawnFn;
  /** Restart backoff bounds (ms). */
  minBackoffMs?: number;
  maxBackoffMs?: number;
  /** Consecutive failed starts (exit before becoming healthy) before giving up. */
  maxFailedStarts?: number;
  /** Max bytes of a single unterminated stdout line before it is discarded. */
  maxLineBytes?: number;
}

const STDERR_TAIL = 2048;
const HEALTHY_AFTER_MS = 30_000;
const KILL_GRACE_MS = 3000;

/**
 * Supervises one bpftrace child: argv spawn (no shell), bounded line buffer,
 * restart with exponential backoff, and a fatal callback when it never starts.
 */
export class BpftraceSource {
  private child: ChildProcess | null = null;
  private restartTimer: NodeJS.Timeout | null = null;
  private healthyTimer: NodeJS.Timeout | null = null;
  private stopped = true;
  private healthy = false;
  private failedStarts = 0;
  private backoffMs: number;
  private buffer = '';
  private stderrTail = '';
  private overflowLogged = false;
  private readonly spawnFn: SpawnFn;
  private readonly minBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly maxFailedStarts: number;
  private readonly maxLineBytes: number;

  constructor(private readonly opts: BpftraceSourceOptions) {
    this.spawnFn = opts.spawn ?? (nodeSpawn as SpawnFn);
    this.minBackoffMs = opts.minBackoffMs ?? 1000;
    this.maxBackoffMs = opts.maxBackoffMs ?? 60_000;
    this.maxFailedStarts = opts.maxFailedStarts ?? 3;
    this.maxLineBytes = opts.maxLineBytes ?? 64 * 1024;
    this.backoffMs = this.minBackoffMs;
  }

  get running(): boolean {
    return this.child !== null;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.launch();
  }

  stop(): void {
    this.stopped = true;
    if (this.restartTimer) clearTimeout(this.restartTimer);
    if (this.healthyTimer) clearTimeout(this.healthyTimer);
    this.restartTimer = null;
    this.healthyTimer = null;
    const child = this.child;
    this.child = null;
    if (child && child.exitCode === null && child.signalCode === null) {
      try { child.kill('SIGTERM'); } catch { /* already gone */ }
      const killer = setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) {
          try { child.kill('SIGKILL'); } catch { /* already gone */ }
        }
      }, KILL_GRACE_MS);
      killer.unref?.();
    }
    this.buffer = '';
  }

  /** Feed raw stdout; exposed for tests. */
  ingest(chunk: string): void {
    this.buffer += chunk;
    let newline = this.buffer.indexOf('\n');
    while (newline >= 0) {
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      this.handleLine(line);
      newline = this.buffer.indexOf('\n');
    }
    if (this.buffer.length > this.maxLineBytes) {
      if (!this.overflowLogged) this.opts.log(`[edr] discarded an oversized bpftrace output line (>${this.maxLineBytes} bytes)`);
      this.overflowLogged = true;
      this.buffer = '';
    }
  }

  private handleLine(line: string): void {
    if (line.length > this.maxLineBytes) return;
    const parsed = parseBpftraceLine(line);
    if (!parsed) return;
    if (parsed.type === 'event') {
      this.markHealthy();
      this.opts.onEvent(parsed.event);
    } else if (parsed.type === 'attached') {
      this.markHealthy();
      this.opts.log(`[edr] bpftrace attached ${parsed.probes} probe(s)`);
    } else if (parsed.type === 'lost') {
      this.opts.log(`[edr] bpftrace dropped ${parsed.count} event(s) (perf buffer full)`);
    } else if (parsed.type === 'error') {
      this.opts.log(`[edr] bpftrace: ${parsed.message}`);
    }
  }

  private markHealthy(): void {
    if (this.healthy) return;
    this.healthy = true;
    this.failedStarts = 0;
    this.backoffMs = this.minBackoffMs;
  }

  private launch(): void {
    if (this.stopped) return;
    this.healthy = false;
    this.buffer = '';
    this.stderrTail = '';
    let child: ChildProcess;
    try {
      child = this.spawnFn(this.opts.bpftracePath, bpftraceArgs({ network: this.opts.network, peers: this.opts.peers }), {
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
        env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C' },
      });
    } catch (error) {
      this.onExit(null, null, (error as Error).message);
      return;
    }
    this.child = child;
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => { if (this.child === child) this.ingest(chunk); });
    child.stderr?.on('data', (chunk: string) => {
      this.stderrTail = (this.stderrTail + chunk).slice(-STDERR_TAIL);
    });
    let finished = false;
    const finish = (code: number | null, signal: NodeJS.Signals | null, error?: string) => {
      if (finished) return;
      finished = true;
      if (this.child !== child) return; // stopped or replaced
      this.child = null;
      this.onExit(code, signal, error);
    };
    child.on('error', (error) => finish(null, null, error.message));
    child.on('exit', (code, signal) => finish(code, signal));
    // A child that stays up for a while without output (quiet host) is healthy too.
    if (this.healthyTimer) clearTimeout(this.healthyTimer);
    this.healthyTimer = setTimeout(() => { if (this.child === child) this.markHealthy(); }, HEALTHY_AFTER_MS);
    this.healthyTimer.unref?.();
  }

  private onExit(code: number | null, signal: NodeJS.Signals | null, error?: string): void {
    if (this.healthyTimer) clearTimeout(this.healthyTimer);
    this.healthyTimer = null;
    if (this.stopped) return;
    const detail = error ?? (this.stderrTail.trim().split('\n').slice(-1)[0] || `exit ${code ?? signal ?? 'unknown'}`);
    if (!this.healthy) this.failedStarts++;
    if (!this.healthy && this.failedStarts >= this.maxFailedStarts) {
      this.stopped = true;
      this.opts.onFatal(`bpftrace failed to start ${this.failedStarts} time(s): ${detail.slice(0, 300)}`);
      return;
    }
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.maxBackoffMs, this.backoffMs * 2);
    this.opts.log(`[edr] bpftrace exited (${detail.slice(0, 300)}); restarting in ${Math.round(delay / 1000)}s`);
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      this.launch();
    }, delay);
    this.restartTimer.unref?.();
  }
}
