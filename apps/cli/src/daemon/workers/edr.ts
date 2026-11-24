import { accessSync, constants, existsSync, readFileSync, readlinkSync, readdirSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, normalize, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { LogTail } from '../../core/log-tail.js';
import { insertEvent } from '../../core/state.js';
import type { EdrSection } from '../../types/config.js';
import type { ThreatEvent } from '../../types/events.js';
import {
  BpftraceSource,
  probeHost,
  selectEdrSource,
  type EbpfProcessEvent,
  type EdrSourceKind,
  type EdrSourceSetting,
  type SourceProbe,
  type SourceSelection,
} from './edr-ebpf.js';

const DEFAULT_AUDIT_LOG = '/var/log/audit/audit.log';
const DEFAULT_WEB_USERS = ['www-data', 'nginx', 'apache', 'httpd', 'caddy', 'node'];
const DEFAULT_TEMP_PATHS = ['/tmp', '/var/tmp', '/dev/shm'];
const MAX_SEEN_EVENTS = 4096;
const WEB_KEY = 'threatcrush_edr_web';
const TEMP_KEY = 'threatcrush_edr_temp';
const MINER_KEY = 'threatcrush_edr_miner';
const CONNECT_KEY = 'threatcrush_edr_connect';
const LISTEN_KEY = 'threatcrush_edr_listen';
const CPU_SAMPLE_MS = 15_000;
const CPU_SUSTAIN_MS = 60_000;
const CPU_THRESHOLD_PERCENT = 80;

const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh', 'fish']);
const DOWNLOADERS = new Set(['curl', 'wget']);
const MINERS = new Set(['xmrig', 'minerd', 'cpuminer', 'cpuminer-multi', 'kdevtmpfsi', 'kinsing', 'cryptonight']);

export interface EdrSettings {
  enabled: boolean;
  /** Event source: auditd log tail, bpftrace (eBPF), or auto-detect. */
  source: EdrSourceSetting;
  auditLogPath: string;
  webServiceUsers: string[];
  tempExecPaths: string[];
  watchNetworkSyscalls: boolean;
  /** Look every traced connection's remote address up in the threat feeds (eBPF source only). */
  matchThreatFeeds: boolean;
  networkBaselineMs: number;
  watchUnknownTempCpu: boolean;
  pollMs: number;
}

function safeAbsolutePath(value: unknown): string | null {
  if (typeof value !== 'string' || !isAbsolute(value) || value.split(sep).includes('..')) return null;
  const path = normalize(value);
  return path === '/' ? null : path;
}

export function edrSettings(section: EdrSection | undefined): EdrSettings {
  const configuredLog = safeAbsolutePath(section?.audit_log_path) ?? DEFAULT_AUDIT_LOG;
  const configuredUsers = Array.isArray(section?.web_service_users)
    ? [...new Set(section.web_service_users.map((value) => String(value).trim()).filter((value) => /^[a-z_][a-z0-9_-]*\$?$/i.test(value)))]
    : DEFAULT_WEB_USERS;
  const configuredPaths = Array.isArray(section?.temp_exec_paths)
    ? [...new Set(section.temp_exec_paths.map(safeAbsolutePath).filter((path): path is string => path !== null))]
    : DEFAULT_TEMP_PATHS;
  const seconds = section?.poll_interval_seconds;
  const pollMs = typeof seconds === 'number' && Number.isFinite(seconds)
    ? Math.max(1, Math.min(60, Math.floor(seconds))) * 1000
    : 2000;
  const baselineSeconds = section?.network_baseline_seconds;
  const source: EdrSourceSetting = section?.source === 'auto' || section?.source === 'ebpf' ? section.source : 'auditd';
  return {
    enabled: section?.enabled === true,
    source,
    auditLogPath: configuredLog,
    webServiceUsers: configuredUsers,
    tempExecPaths: configuredPaths,
    watchNetworkSyscalls: section?.watch_network_syscalls === true,
    matchThreatFeeds: section?.watch_network_syscalls === true && section?.match_threat_feeds !== false,
    networkBaselineMs: typeof baselineSeconds === 'number' && Number.isFinite(baselineSeconds)
      ? Math.max(0, Math.min(3600, Math.floor(baselineSeconds))) * 1000
      : 60_000,
    watchUnknownTempCpu: section?.watch_unknown_temp_cpu !== false,
    pollMs,
  };
}

export interface AuditRecord {
  timestamp: Date;
  /** Which event source produced the record. Absent means auditd. */
  source?: EdrSourceKind;
  serial: string;
  key: string;
  executable: string;
  comm: string;
  euid: number;
  pid?: number;
  ppid?: number;
}

function parseAuditFields(line: string): Record<string, string> {
  const fields: Record<string, string> = {};
  const pattern = /(?:^|\s)([A-Za-z0-9_]+)=("(?:\\.|[^"\\])*"|\S+)/g;
  for (const match of line.matchAll(pattern)) {
    const raw = match[2];
    fields[match[1]] = raw.startsWith('"') && raw.endsWith('"')
      ? raw.slice(1, -1).replace(/\\(["\\])/g, '$1')
      : raw;
  }
  return fields;
}

/** One keyed SYSCALL record is enough for our rules; EXECVE args are intentionally ignored. */
function parseAuditRecord(line: string): AuditRecord | null {
  const header = /^type=SYSCALL\b.*?\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\):/.exec(line);
  if (!header) return null;
  const fields = parseAuditFields(line);
  if (fields.success !== 'yes' || !fields.key || fields.key === '(null)') return null;
  const executable = fields.exe ?? '';
  const euid = Number(fields.euid);
  const seconds = Number(header[1]);
  if (!executable.startsWith('/') || !Number.isInteger(euid) || !Number.isFinite(seconds)) return null;
  const pid = Number(fields.pid);
  const ppid = Number(fields.ppid);
  return {
    timestamp: new Date(seconds * 1000),
    serial: header[2],
    key: fields.key,
    executable,
    comm: fields.comm ?? basename(executable),
    euid,
    ...(Number.isInteger(pid) && pid > 0 ? { pid } : {}),
    ...(Number.isInteger(ppid) && ppid > 0 ? { ppid } : {}),
  };
}

/** Execution parser retained for callers that need only execution-rule records. */
export function parseAuditExecution(line: string): AuditRecord | null {
  return parseAuditRecord(line);
}

function accountNames(): Map<number, string> {
  let raw = '';
  try {
    raw = execFileSync('getent', ['passwd'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    try { raw = readFileSync('/etc/passwd', 'utf8'); } catch { return new Map(); }
  }
  const out = new Map<number, string>();
  for (const line of raw.split('\n')) {
    const fields = line.split(':');
    const uid = Number(fields[2]);
    if (fields[0] && Number.isInteger(uid)) out.set(uid, fields[0]);
  }
  return out;
}

function pathWithin(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root.replace(/\/$/, '')}/`);
}

function executableInWorldWritableDirectory(executable: string): boolean {
  try { return (statSync(dirname(executable)).mode & 0o002) !== 0; } catch { return false; }
}

function clean(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 400);
}

const EXEC_KEYS = [MINER_KEY, WEB_KEY, TEMP_KEY];
const MAX_EBPF_EXE_CACHE = 4096;

/**
 * Normalize one eBPF event into the record shape the auditd parser produces,
 * so the same classifier runs on either source. auditd tags records with the
 * key of the narrow rule that matched; eBPF sees every exec, so an exec is
 * offered to each execution rule key in severity order and the classifier
 * decides which (if any) applies. `resolveExe` maps a pid to its real binary
 * (auditd's `exe=`); a relative or unresolvable path is dropped.
 */
export function ebpfEventToRecords(
  event: EbpfProcessEvent,
  resolveExe: (pid: number) => string | null,
  now: Date = new Date(),
  serial = 'ebpf',
): AuditRecord[] {
  let executable = resolveExe(event.pid);
  if (!executable && event.kind === 'exec' && event.filename?.startsWith('/')) executable = event.filename;
  if (!executable || !executable.startsWith('/')) return [];
  const base = {
    timestamp: now,
    source: 'ebpf' as const,
    serial,
    executable,
    comm: event.comm || basename(executable),
    euid: event.euid,
    pid: event.pid,
    ...(event.ppid > 0 ? { ppid: event.ppid } : {}),
  };
  if (event.kind === 'connect') return [{ ...base, key: CONNECT_KEY }];
  if (event.kind === 'listen') return [{ ...base, key: LISTEN_KEY }];
  return EXEC_KEYS.map((key) => ({ ...base, key }));
}

export interface EdrSourceStatus {
  configured: EdrSourceSetting;
  active: EdrSourceKind | 'none';
  reason: string;
  updated_at: string;
  pid: number;
}

/** One outbound TCP connect seen by the eBPF source. */
export interface TracedConnection {
  peerIp: string;
  peerPort: number;
  pid: number;
  comm: string;
  euid: number;
  /**
   * The connecting binary, when /proc still has it. Lazy on purpose: a busy
   * proxy opens hundreds of connections a second and almost none are listed,
   * so the receiver resolves it only after an address matches.
   */
  resolveExecutable: () => string | null;
}

export interface EdrOptions {
  bus: { publish(event: ThreatEvent): void };
  settings: EdrSettings;
  /** Root-owned file used to retain the learned outbound executable set. */
  networkBaselinePath?: string;
  /** Where the daemon records which event source is active (read by `threatcrush edr status`). */
  sourceStatusPath?: string;
  /** Host facts for source selection; injectable for tests. */
  probeHost?: (configured: EdrSourceSetting) => SourceProbe;
  /**
   * Called for every traced outbound connection when `match_threat_feeds` is
   * on. The receiver matches the address against the threat feeds and keeps
   * nothing on a miss.
   */
  onConnection?: (conn: TracedConnection) => void;
  /** bpftrace supervisor factory; injectable for tests. */
  createBpftrace?: (opts: ConstructorParameters<typeof BpftraceSource>[0]) => Pick<BpftraceSource, 'start' | 'stop'>;
  log: (line: string) => void;
}

export function readEdrSourceStatus(path: string): EdrSourceStatus | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<EdrSourceStatus>;
    if (parsed.active !== 'auditd' && parsed.active !== 'ebpf' && parsed.active !== 'none') return null;
    return parsed as EdrSourceStatus;
  } catch {
    return null;
  }
}

interface CpuSample {
  ticks: number;
  firstAt: number;
  accumulatedTicks: number;
  alerted: boolean;
}

export class EdrWatch {
  private tail: LogTail | null = null;
  private bpftrace: Pick<BpftraceSource, 'start' | 'stop'> | null = null;
  private ebpfSerial = 0;
  private readonly ebpfExeCache = new Map<number, string>();
  private activeSource: EdrSourceKind | 'none' = 'none';
  private timer: NodeJS.Timeout | null = null;
  private cpuTimer: NodeJS.Timeout | null = null;
  private readonly usersById: Map<number, string>;
  private readonly webIds: Set<number>;
  private readonly seen = new Set<string>();
  private readonly listenersSeen = new Set<string>();
  private readonly outboundExecutables = new Set<string>();
  private readonly cpuSamples = new Map<string, CpuSample>();
  private readonly networkStartedAt = Date.now();
  private readonly ticksPerSecond = this.readTicksPerSecond();
  private baselineWriteFailed = false;

  constructor(private readonly opts: EdrOptions) {
    this.usersById = accountNames();
    const wanted = new Set(opts.settings.webServiceUsers.map((name) => name.toLowerCase()));
    this.webIds = new Set([...this.usersById].filter(([, name]) => wanted.has(name.toLowerCase())).map(([uid]) => uid));
    this.loadNetworkBaseline();
  }

  start(): void {
    if (!this.opts.settings.enabled) {
      this.opts.log('[edr] disabled; set [edr] enabled = true after installing the generated audit rules');
      return;
    }
    const probe = this.probe();
    const selection = selectEdrSource(probe);
    if (selection.source === 'ebpf' && probe.bpftracePath) {
      this.startEbpf(probe.bpftracePath, selection.reason);
    } else {
      if (selection.degraded) this.opts.log(`[edr] source = "ebpf" requested but ${selection.reason}`);
      this.startAuditd(selection.reason);
    }
    if (this.opts.settings.watchUnknownTempCpu) {
      this.cpuTimer = setInterval(() => this.sampleTemporaryProcesses(), CPU_SAMPLE_MS);
      this.cpuTimer.unref?.();
      this.sampleTemporaryProcesses();
      this.opts.log(`[edr] watching temporary-path processes for sustained CPU use (${CPU_THRESHOLD_PERCENT}% for ${CPU_SUSTAIN_MS / 1000}s)`);
    }
  }

  /** The event source currently feeding detections. */
  get source(): EdrSourceKind | 'none' {
    return this.activeSource;
  }

  private probe(): SourceProbe {
    const configured = this.opts.settings.source;
    if (configured === 'auditd') return { configured, bpftracePath: null, btfPresent: false, isRoot: false };
    return (this.opts.probeHost ?? probeHost)(configured);
  }

  private startEbpf(bpftracePath: string, reason: string): void {
    const options = {
      bpftracePath,
      network: this.opts.settings.watchNetworkSyscalls,
      peers: this.opts.settings.matchThreatFeeds,
      onEvent: (event: EbpfProcessEvent) => { this.handleEbpfEvent(event); },
      onFatal: (failure: string) => {
        this.bpftrace = null;
        this.opts.log(`[edr] ${failure}; falling back to auditd`);
        this.startAuditd(`eBPF failed: ${failure}`);
      },
      log: this.opts.log,
    };
    this.bpftrace = this.opts.createBpftrace ? this.opts.createBpftrace(options) : new BpftraceSource(options);
    this.setSource('ebpf', reason);
    const addresses = this.opts.settings.matchThreatFeeds
      ? 'command arguments are not collected; remote addresses are matched against the threat feeds and kept only on a hit'
      : 'command arguments and remote addresses are not collected';
    this.opts.log(`[edr] event source: eBPF via ${bpftracePath} (exec${this.opts.settings.watchNetworkSyscalls ? ', tcp connect/listen' : ''}); ${addresses}`);
    this.bpftrace.start();
  }

  private startAuditd(reason: string): void {
    if (!existsSync(this.opts.settings.auditLogPath)) {
      this.opts.log(`[edr] audit log not found at ${this.opts.settings.auditLogPath}; auditd detections are unavailable`);
      this.setSource('none', `${reason}; audit log not found at ${this.opts.settings.auditLogPath}`);
      return;
    }
    try {
      accessSync(this.opts.settings.auditLogPath, constants.R_OK);
      this.tail = new LogTail(this.opts.settings.auditLogPath);
      this.timer = setInterval(() => this.poll(), this.opts.settings.pollMs);
      this.timer.unref?.();
      this.setSource('auditd', reason);
      this.opts.log(`[edr] event source: auditd; watching selected events in ${this.opts.settings.auditLogPath}; command arguments and remote addresses are discarded`);
    } catch {
      this.opts.log(`[edr] cannot read ${this.opts.settings.auditLogPath}; run the daemon with permission to read the audit log`);
      this.setSource('none', `${reason}; cannot read ${this.opts.settings.auditLogPath}`);
    }
  }

  private setSource(active: EdrSourceKind | 'none', reason: string): void {
    this.activeSource = active;
    const path = this.opts.sourceStatusPath;
    if (!path) return;
    const status: EdrSourceStatus = {
      configured: this.opts.settings.source,
      active,
      reason,
      updated_at: new Date().toISOString(),
      pid: process.pid,
    };
    try {
      const temp = `${path}.${process.pid}.tmp`;
      writeFileSync(temp, `${JSON.stringify(status)}\n`, { mode: 0o644 });
      renameSync(temp, path);
    } catch { /* status file is informational */ }
  }

  private resolveEbpfExe(event: EbpfProcessEvent): string | null {
    let exe: string | null = null;
    try { exe = readlinkSync(`/proc/${event.pid}/exe`).replace(/ \(deleted\)$/, ''); } catch { /* process already exited */ }
    if (!exe && event.kind !== 'exec') exe = this.ebpfExeCache.get(event.pid) ?? null;
    if (!exe && event.kind === 'exec' && event.filename?.startsWith('/')) exe = event.filename;
    if (exe && event.kind === 'exec') {
      this.ebpfExeCache.delete(event.pid);
      this.ebpfExeCache.set(event.pid, exe);
      if (this.ebpfExeCache.size > MAX_EBPF_EXE_CACHE) this.ebpfExeCache.delete(this.ebpfExeCache.keys().next().value as number);
    }
    return exe;
  }

  /** Classify one eBPF event through the same rules as auditd records. Returns the event published, if any. */
  handleEbpfEvent(event: EbpfProcessEvent, resolveExe?: (pid: number) => string | null): ThreatEvent | null {
    if ((event.kind === 'connect' || event.kind === 'listen') && !this.opts.settings.watchNetworkSyscalls) return null;
    this.ebpfSerial = (this.ebpfSerial + 1) % Number.MAX_SAFE_INTEGER;
    const resolver = resolveExe ?? (() => this.resolveEbpfExe(event));
    if (event.kind === 'connect' && event.peerIp && event.peerPort !== undefined && this.opts.settings.matchThreatFeeds && this.opts.onConnection) {
      try {
        this.opts.onConnection({
          peerIp: event.peerIp,
          peerPort: event.peerPort,
          pid: event.pid,
          comm: event.comm,
          euid: event.euid,
          resolveExecutable: () => resolver(event.pid),
        });
      } catch { /* a feed lookup must never stop process detections */ }
    }
    const records = ebpfEventToRecords(event, resolver, new Date(), `ebpf-${this.ebpfSerial}`);
    for (const record of records) {
      const threat = this.classify(record);
      if (threat) {
        this.publish(threat);
        return threat;
      }
    }
    return null;
  }

  stop(): void {
    try { this.bpftrace?.stop(); } catch { /* child already gone */ }
    this.bpftrace = null;
    this.ebpfExeCache.clear();
    this.activeSource = 'none';
    if (this.timer) clearInterval(this.timer);
    if (this.cpuTimer) clearInterval(this.cpuTimer);
    this.timer = null;
    this.cpuTimer = null;
    this.tail = null;
    this.seen.clear();
    this.listenersSeen.clear();
    this.cpuSamples.clear();
  }

  poll(): number {
    if (!this.tail) return 0;
    return this.tail.poll((line) => {
      const record = parseAuditRecord(line);
      if (!record) return;
      const dedupeKey = `${record.timestamp.getTime()}:${record.serial}:${record.key}`;
      if (this.seen.has(dedupeKey)) return;
      this.seen.add(dedupeKey);
      if (this.seen.size > MAX_SEEN_EVENTS) this.seen.delete(this.seen.values().next().value as string);
      const event = this.classify(record);
      if (!event) return;
      this.publish(event);
    });
  }

  private publish(event: ThreatEvent): void {
    try { insertEvent(event); } catch { /* state database is optional */ }
    this.opts.bus.publish(event);
  }

  private classify(execution: AuditRecord): ThreatEvent | null {
    const name = basename(execution.executable).toLowerCase();
    const account = this.usersById.get(execution.euid) ?? String(execution.euid);
    let severity: ThreatEvent['severity'];
    let ruleId: string;
    let message: string;

    if (execution.key === CONNECT_KEY) {
      const wasKnown = this.outboundExecutables.has(execution.executable);
      this.rememberOutboundExecutable(execution.executable);
      if (SHELLS.has(name) || SHELLS.has(execution.comm.toLowerCase())) {
        severity = 'high';
        ruleId = 'edr-shell-network-connect';
        message = `Possible reverse-shell behavior: shell ${execution.executable} opened an outbound connection`;
      } else if (!wasKnown && Date.now() - this.networkStartedAt >= this.opts.settings.networkBaselineMs) {
        severity = 'medium';
        ruleId = 'edr-new-outbound-executable';
        message = `Previously unseen executable opened an outbound connection: ${execution.executable}`;
      } else {
        return null;
      }
    } else if (execution.key === LISTEN_KEY) {
      const listenerKey = `${execution.pid ?? execution.serial}:${execution.executable}`;
      if (this.listenersSeen.has(listenerKey)) return null;
      this.listenersSeen.add(listenerKey);
      if (this.listenersSeen.size > MAX_SEEN_EVENTS) this.listenersSeen.delete(this.listenersSeen.values().next().value as string);
      severity = 'medium';
      ruleId = 'edr-process-listener';
      message = `Process began listening for inbound connections: ${execution.executable}`;
    } else if (execution.key === WEB_KEY && this.webIds.has(execution.euid) && (SHELLS.has(name) || DOWNLOADERS.has(name))) {
      severity = 'high';
      ruleId = 'edr-web-service-tool';
      message = `Web service account ${account} executed ${name}: ${execution.executable}`;
    } else if (execution.key === TEMP_KEY && (
      this.opts.settings.tempExecPaths.some((path) => pathWithin(execution.executable, path)) ||
      executableInWorldWritableDirectory(execution.executable)
    )) {
      severity = 'high';
      ruleId = 'edr-writable-path-execution';
      message = `Executable launched from a temporary or world-writable directory: ${execution.executable}`;
    } else if (execution.key === MINER_KEY && MINERS.has(name)) {
      severity = 'critical';
      ruleId = 'edr-known-miner-execution';
      message = `Known cryptocurrency miner executed: ${execution.executable}`;
    } else {
      return null;
    }

    return {
      timestamp: execution.timestamp,
      module: 'edr',
      category: 'system',
      severity,
      message: clean(message),
      details: {
        rule_id: ruleId,
        executable: clean(execution.executable),
        account,
        euid: execution.euid,
        ...(execution.pid ? { pid: execution.pid } : {}),
        ...(execution.ppid ? { ppid: execution.ppid } : {}),
        event_source: execution.source ?? 'auditd',
        ...(execution.source === 'ebpf' ? {} : { audit_serial: execution.serial }),
      },
    };
  }

  private loadNetworkBaseline(): void {
    const path = this.opts.networkBaselinePath;
    if (!path) return;
    try {
      const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
      if (Array.isArray(parsed)) {
        for (const value of parsed.slice(0, 10_000)) {
          if (typeof value === 'string' && value.startsWith('/')) this.outboundExecutables.add(value);
        }
      }
    } catch { /* a missing or invalid baseline starts a fresh learning window */ }
  }

  private rememberOutboundExecutable(executable: string): void {
    if (this.outboundExecutables.has(executable)) return;
    this.outboundExecutables.add(executable);
    if (this.outboundExecutables.size > 10_000) this.outboundExecutables.delete(this.outboundExecutables.values().next().value as string);
    const path = this.opts.networkBaselinePath;
    if (!path) return;
    try {
      const temp = `${path}.${process.pid}.tmp`;
      writeFileSync(temp, `${JSON.stringify([...this.outboundExecutables])}\n`, { mode: 0o600 });
      renameSync(temp, path);
      this.baselineWriteFailed = false;
    } catch (error) {
      if (!this.baselineWriteFailed) this.opts.log(`[edr] could not persist outbound executable baseline: ${(error as Error).message.split('\n')[0]}`);
      this.baselineWriteFailed = true;
    }
  }

  private readTicksPerSecond(): number {
    try {
      const value = Number(execFileSync('getconf', ['CLK_TCK'], { encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore'] }).trim());
      if (Number.isFinite(value) && value > 0) return value;
    } catch { /* Linux commonly uses 100 clock ticks per second. */ }
    return 100;
  }

  private sampleTemporaryProcesses(): void {
    if (!this.opts.settings.enabled || !this.opts.settings.watchUnknownTempCpu) return;
    const now = Date.now();
    const current = new Map<string, CpuSample>();
    let pids: string[];
    try { pids = readdirSync('/proc'); } catch { return; }
    for (const pid of pids) {
      if (!/^\d+$/.test(pid)) continue;
      const proc = `/proc/${pid}`;
      try {
        const raw = readFileSync(`${proc}/stat`, 'utf8');
        const end = raw.lastIndexOf(')');
        if (end < 0) continue;
        const fields = raw.slice(end + 1).trim().split(/\s+/);
        const userTicks = Number(fields[11]);
        const systemTicks = Number(fields[12]);
        const startTicks = fields[19];
        if (!Number.isFinite(userTicks) || !Number.isFinite(systemTicks) || !startTicks) continue;
        let executable = readlinkSync(`${proc}/exe`);
        executable = executable.replace(/ \(deleted\)$/, '');
        if (!this.opts.settings.tempExecPaths.some((path) => pathWithin(executable, path))) continue;
        const name = basename(executable).toLowerCase();
        if (MINERS.has(name)) continue; // the execution rule already gives named miners a critical alert
        const key = `${pid}:${startTicks}`;
        const ticks = userTicks + systemTicks;
        const previous = this.cpuSamples.get(key);
        if (!previous) {
          current.set(key, { ticks, firstAt: now, accumulatedTicks: 0, alerted: false });
          continue;
        }
        const delta = Math.max(0, ticks - previous.ticks);
        const accumulatedTicks = previous.accumulatedTicks + delta;
        const elapsedMs = Math.max(1, now - previous.firstAt);
        const cpuPercent = accumulatedTicks * 100_000 / (this.ticksPerSecond * elapsedMs);
        const sample: CpuSample = { ticks, firstAt: previous.firstAt, accumulatedTicks, alerted: previous.alerted };
        current.set(key, sample);
        if (!sample.alerted && elapsedMs >= CPU_SUSTAIN_MS && cpuPercent >= CPU_THRESHOLD_PERCENT) {
          sample.alerted = true;
          const event: ThreatEvent = {
            timestamp: new Date(now),
            module: 'edr',
            category: 'system',
            severity: 'high',
            message: `Unknown executable in a temporary directory sustained ${cpuPercent.toFixed(0)}% CPU: ${clean(executable)}`,
            details: { rule_id: 'edr-temp-high-cpu', executable: clean(executable), pid: Number(pid), cpu_percent: Number(cpuPercent.toFixed(1)), sustained_seconds: Math.floor(elapsedMs / 1000) },
          };
          this.publish(event);
        }
      } catch { /* processes exit and procfs permissions may change between reads */ }
    }
    this.cpuSamples.clear();
    for (const [key, sample] of current) this.cpuSamples.set(key, sample);
  }
}
