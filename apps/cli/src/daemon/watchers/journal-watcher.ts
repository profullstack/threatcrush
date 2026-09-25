import { spawn, type ChildProcess, spawnSync } from 'node:child_process';
import type { EventBus } from '../event-bus.js';
import { classifySshAuth, parseAuthMessage } from '../../core/log-parser.js';
import { insertEvent } from '../../core/state.js';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';

/**
 * The process names sshd logs authentication under: `sshd`, and since OpenSSH
 * 9.8 the per-connection `sshd-session`.
 */
export const SSHD_COMMS = ['sshd', 'sshd-session'];

/**
 * Whether journald says root's sshd logged this record. Only the fields
 * journald fills in itself count: SYSLOG_IDENTIFIER is whatever the sender
 * claims, so `logger -t sshd "Failed password for root from <ip>"` from any
 * local account would otherwise get that address banned.
 */
export function isSshdRecord(entry: Record<string, unknown>): boolean {
  return entry._UID === '0' && SSHD_COMMS.includes(entry._COMM as string);
}

/**
 * The ssh-guard event for one journald record from sshd — the same event
 * log-watcher makes of the same line in auth.log — or null when the record is
 * not sshd's or is not a failed, invalid-user or accepted login.
 */
export function sshEventFromJournal(entry: Record<string, unknown>): ThreatEvent | null {
  if (!isSshdRecord(entry) || typeof entry.MESSAGE !== 'string') return null;
  const timestamp = realtimeToDate(entry.__REALTIME_TIMESTAMP as string | undefined) || new Date();
  const verdict = classifySshAuth(parseAuthMessage(entry._COMM as string, entry.MESSAGE, timestamp));
  if (!verdict) return null;
  return {
    timestamp,
    module: 'ssh-guard',
    category: 'auth',
    severity: verdict.severity,
    message: verdict.message,
    source_ip: verdict.source_ip,
  };
}

/** `running`, or why sshd's journal records cannot be followed. */
export type SshdJournalState = 'running' | 'unreadable' | 'unavailable';

// Wraps `journalctl --user -o json -f` so threatcrushd can pick up user-session
// events without needing to belong to the `adm` or `systemd-journal` group.
// On systems without journalctl this watcher is a no-op.
//
// startSshd() adds a second tail: sshd's records from the SYSTEM journal, as
// ssh-guard events. The daemon calls it only when no auth log is tailed.
export class JournalWatcher {
  private proc: ChildProcess | null = null;
  private sshdProc: ChildProcess | null = null;
  private buffer = '';
  private sshdBuffer = '';
  private moduleName = 'user-journal';
  private active = false;

  constructor(private bus: EventBus) {}

  // When the daemon runs as root (system mode), tail the SYSTEM journal so
  // we pick up sshd / sudo / kernel / UFW events. Falling back to --user
  // would give us root's mostly-empty per-user journal. Otherwise we use
  // --user so the daemon can run unprivileged on a workstation.
  static scopeArgs(): string[] {
    const isRoot = process.platform === 'linux'
      && typeof process.getuid === 'function'
      && process.getuid() === 0;
    return isRoot ? [] : ['--user'];
  }

  static isAvailable(): boolean {
    const probe = spawnSync('journalctl', [...this.scopeArgs(), '-n', '0', '--no-pager'], {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return probe.status === 0;
  }

  start(): boolean {
    if (!JournalWatcher.isAvailable()) return false;

    const child = spawn(
      'journalctl',
      [...JournalWatcher.scopeArgs(), '-o', 'json', '-f', '--since', 'now'],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    if (!child.stdout) return false;
    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (chunk: string) => {
      this.buffer = this.drain(this.buffer + chunk, (entry) => this.handleEntry(entry));
    });
    child.on('exit', () => {
      this.proc = null;
      this.active = false;
    });
    this.proc = child;

    this.active = true;
    return true;
  }

  /**
   * Follows sshd in the system journal. Unprivileged, that needs the adm,
   * systemd-journal or wheel group; without it journalctl shows only the
   * user's own records, so this reports `unreadable` rather than tailing
   * nothing and looking like protection.
   */
  startSshd(): SshdJournalState {
    // Every booted system journal holds records from root; not seeing one
    // means the system journal is closed to us.
    const probe = spawnSync('journalctl', ['-q', '-n', '1', '-o', 'cat', '--no-pager', '_UID=0'], {
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf-8',
    });
    if (probe.error || probe.status !== 0) return 'unavailable';
    if (!probe.stdout.trim()) return 'unreadable';

    // Same field twice is OR, different fields AND: root's sshd or sshd-session.
    const matches = ['_UID=0', ...SSHD_COMMS.map((comm) => `_COMM=${comm}`)];
    const child = spawn('journalctl', ['-o', 'json', '-f', '--since', 'now', ...matches], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    if (!child.stdout) return 'unavailable';
    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (chunk: string) => {
      this.sshdBuffer = this.drain(this.sshdBuffer + chunk, (entry) => {
        const event = sshEventFromJournal(entry);
        if (event) this.emit(event);
      });
    });
    child.on('error', () => { this.sshdProc = null; });
    child.on('exit', () => { this.sshdProc = null; });
    this.sshdProc = child;
    return 'running';
  }

  stop(): void {
    for (const child of [this.proc, this.sshdProc]) {
      try { child?.kill('SIGTERM'); } catch {}
    }
    this.proc = null;
    this.sshdProc = null;
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  moduleNameValue(): string {
    return this.moduleName;
  }

  /** Hands each complete JSON line to `onEntry`; returns the unterminated rest. */
  private drain(buffer: string, onEntry: (entry: Record<string, unknown>) => void): string {
    let idx;
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;
      let entry: Record<string, unknown>;
      try {
        entry = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      onEntry(entry);
    }
    return buffer;
  }

  private handleEntry(entry: Record<string, unknown>): void {
    // The sshd tail reports these as ssh-guard events; once is enough.
    if (this.sshdProc && isSshdRecord(entry)) return;

    const message = entry.MESSAGE as string | undefined;
    if (!message) return;

    const priority = parseInt((entry.PRIORITY as string | undefined) ?? '6', 10);
    const severity = priorityToSeverity(priority);

    // Surface a couple of common suspicious-looking sources at a higher
    // severity even if the kernel disagrees with us.
    const ident = (entry.SYSLOG_IDENTIFIER || entry._COMM || 'journal') as string;
    const bumpedSeverity = bumpForIdent(ident, message, severity);

    this.emit({
      timestamp: realtimeToDate(entry.__REALTIME_TIMESTAMP as string | undefined) || new Date(),
      module: this.moduleName,
      category: 'system',
      severity: bumpedSeverity,
      message: `[${ident}] ${message}`.slice(0, 500),
    });
  }

  private emit(event: ThreatEvent): void {
    try { insertEvent(event); } catch { /* db optional */ }
    this.bus.publish(event);
  }
}

function priorityToSeverity(priority: number): EventSeverity {
  // syslog priorities: 0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5 notice, 6 info, 7 debug
  if (priority <= 2) return 'critical';
  if (priority === 3) return 'high';
  if (priority === 4) return 'medium';
  if (priority === 5) return 'low';
  return 'info';
}

function bumpForIdent(ident: string, message: string, base: EventSeverity): EventSeverity {
  if (/sudo/i.test(ident) && /authentication failure|incorrect password|FAILED/i.test(message)) {
    return 'high';
  }
  if (/sshd/i.test(ident) && /failed|invalid user|break-in/i.test(message)) {
    return 'high';
  }
  return base;
}

function realtimeToDate(rt: string | undefined): Date | null {
  if (!rt) return null;
  const us = parseInt(rt, 10);
  if (!Number.isFinite(us)) return null;
  return new Date(Math.floor(us / 1000));
}
