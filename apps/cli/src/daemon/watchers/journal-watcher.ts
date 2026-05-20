import { spawn, type ChildProcess, spawnSync } from 'node:child_process';
import type { EventBus } from '../event-bus.js';
import { insertEvent } from '../../core/state.js';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';

// Wraps `journalctl --user -o json -f` so threatcrushd can pick up user-session
// events without needing to belong to the `adm` or `systemd-journal` group.
// On systems without journalctl this watcher is a no-op.
export class JournalWatcher {
  private proc: ChildProcess | null = null;
  private buffer = '';
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
    child.stdout.on('data', (chunk: string) => this.onData(chunk));
    child.on('exit', () => {
      this.proc = null;
      this.active = false;
    });
    this.proc = child;

    this.active = true;
    return true;
  }

  stop(): void {
    if (this.proc) {
      try { this.proc.kill('SIGTERM'); } catch {}
      this.proc = null;
    }
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  moduleNameValue(): string {
    return this.moduleName;
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let idx;
    while ((idx = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 1);
      if (!line.trim()) continue;
      this.handleLine(line);
    }
  }

  private handleLine(line: string): void {
    let entry: Record<string, string>;
    try {
      entry = JSON.parse(line) as Record<string, string>;
    } catch {
      return;
    }

    const message = entry.MESSAGE;
    if (!message) return;

    const priority = parseInt(entry.PRIORITY ?? '6', 10);
    const severity = priorityToSeverity(priority);

    // Surface a couple of common suspicious-looking sources at a higher
    // severity even if the kernel disagrees with us.
    const ident = entry.SYSLOG_IDENTIFIER || entry._COMM || 'journal';
    const bumpedSeverity = bumpForIdent(ident, message, severity);

    const event: ThreatEvent = {
      timestamp: realtimeToDate(entry.__REALTIME_TIMESTAMP) || new Date(),
      module: this.moduleName,
      category: 'system',
      severity: bumpedSeverity,
      message: `[${ident}] ${message}`.slice(0, 500),
    };

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
