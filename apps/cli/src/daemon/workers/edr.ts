import { accessSync, constants, existsSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, normalize, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { LogTail } from '../../core/log-tail.js';
import { insertEvent } from '../../core/state.js';
import type { EdrSection } from '../../types/config.js';
import type { ThreatEvent } from '../../types/events.js';

const DEFAULT_AUDIT_LOG = '/var/log/audit/audit.log';
const DEFAULT_WEB_USERS = ['www-data', 'nginx', 'apache', 'httpd', 'caddy', 'node'];
const DEFAULT_TEMP_PATHS = ['/tmp', '/var/tmp', '/dev/shm'];
const MAX_SEEN_EVENTS = 4096;
const WEB_KEY = 'threatcrush_edr_web';
const TEMP_KEY = 'threatcrush_edr_temp';
const MINER_KEY = 'threatcrush_edr_miner';

const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh', 'fish']);
const DOWNLOADERS = new Set(['curl', 'wget']);
const MINERS = new Set(['xmrig', 'minerd', 'cpuminer', 'cpuminer-multi', 'kdevtmpfsi', 'kinsing', 'cryptonight']);

export interface EdrSettings {
  enabled: boolean;
  auditLogPath: string;
  webServiceUsers: string[];
  tempExecPaths: string[];
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
  return {
    enabled: section?.enabled === true,
    auditLogPath: configuredLog,
    webServiceUsers: configuredUsers,
    tempExecPaths: configuredPaths,
    pollMs,
  };
}

interface AuditExecution {
  timestamp: Date;
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

/** One SYSCALL record is enough for our rules; EXECVE args are intentionally ignored. */
export function parseAuditExecution(line: string): AuditExecution | null {
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

export interface EdrOptions {
  bus: { publish(event: ThreatEvent): void };
  settings: EdrSettings;
  log: (line: string) => void;
}

export class EdrWatch {
  private tail: LogTail | null = null;
  private timer: NodeJS.Timeout | null = null;
  private readonly usersById: Map<number, string>;
  private readonly webIds: Set<number>;
  private readonly seen = new Set<string>();

  constructor(private readonly opts: EdrOptions) {
    this.usersById = accountNames();
    const wanted = new Set(opts.settings.webServiceUsers.map((name) => name.toLowerCase()));
    this.webIds = new Set([...this.usersById].filter(([, name]) => wanted.has(name.toLowerCase())).map(([uid]) => uid));
  }

  start(): void {
    if (!this.opts.settings.enabled) {
      this.opts.log('[edr] disabled; set [edr] enabled = true after installing the generated audit rules');
      return;
    }
    if (!existsSync(this.opts.settings.auditLogPath)) {
      this.opts.log(`[edr] audit log not found at ${this.opts.settings.auditLogPath}; install and start auditd, then enable its rules`);
      return;
    }
    try { accessSync(this.opts.settings.auditLogPath, constants.R_OK); } catch {
      this.opts.log(`[edr] cannot read ${this.opts.settings.auditLogPath}; run the daemon with permission to read the audit log`);
      return;
    }
    this.tail = new LogTail(this.opts.settings.auditLogPath);
    this.timer = setInterval(() => this.poll(), this.opts.settings.pollMs);
    this.timer.unref?.();
    this.opts.log(`[edr] watching selected auditd events in ${this.opts.settings.auditLogPath}; command arguments are discarded`);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.tail = null;
    this.seen.clear();
  }

  poll(): number {
    if (!this.tail) return 0;
    return this.tail.poll((line) => {
      const execution = parseAuditExecution(line);
      if (!execution) return;
      const dedupeKey = `${execution.timestamp.getTime()}:${execution.serial}:${execution.key}`;
      if (this.seen.has(dedupeKey)) return;
      this.seen.add(dedupeKey);
      if (this.seen.size > MAX_SEEN_EVENTS) this.seen.delete(this.seen.values().next().value as string);
      const event = this.classify(execution);
      if (!event) return;
      try { insertEvent(event); } catch { /* state database is optional */ }
      this.opts.bus.publish(event);
    });
  }

  private classify(execution: AuditExecution): ThreatEvent | null {
    const name = basename(execution.executable).toLowerCase();
    const account = this.usersById.get(execution.euid) ?? String(execution.euid);
    let severity: ThreatEvent['severity'];
    let ruleId: string;
    let message: string;

    if (execution.key === WEB_KEY && this.webIds.has(execution.euid) && (SHELLS.has(name) || DOWNLOADERS.has(name))) {
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
        audit_serial: execution.serial,
      },
    };
  }
}
