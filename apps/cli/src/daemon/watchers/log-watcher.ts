import { existsSync, statSync, createReadStream, accessSync, constants } from 'node:fs';
import { createInterface } from 'node:readline';
import type { EventBus } from '../event-bus.js';
import { autoDetectParser, detectAttackPattern, parseAuthLog, parseNginxLog } from '../../core/log-parser.js';
import { insertEvent } from '../../core/state.js';
import type { ThreatEvent, EventCategory, EventSeverity } from '../../types/events.js';

export interface LogSource {
  path: string;
  module: string;
  category: EventCategory;
}

export const DEFAULT_SOURCES: LogSource[] = [
  { path: '/var/log/auth.log', module: 'ssh-guard', category: 'auth' },
  { path: '/var/log/secure', module: 'ssh-guard', category: 'auth' },
  { path: '/var/log/nginx/access.log', module: 'log-watcher', category: 'web' },
  { path: '/var/log/syslog', module: 'log-watcher', category: 'system' },
];

export class LogWatcher {
  private timers = new Map<string, NodeJS.Timeout>();
  private positions = new Map<string, number>();
  private active = new Set<string>();

  constructor(private bus: EventBus, private sources: LogSource[] = DEFAULT_SOURCES) {}

  start(): string[] {
    const started: string[] = [];
    for (const src of this.sources) {
      if (!existsSync(src.path)) continue;
      try { accessSync(src.path, constants.R_OK); }
      catch { continue; }
      this.tail(src);
      started.push(src.path);
    }
    return started;
  }

  stop(): void {
    for (const t of this.timers.values()) clearInterval(t);
    this.timers.clear();
    this.positions.clear();
    this.active.clear();
  }

  activeModules(): string[] {
    return [...this.active];
  }

  private tail(src: LogSource): void {
    try {
      this.positions.set(src.path, statSync(src.path).size);
    } catch {
      this.positions.set(src.path, 0);
    }

    const timer = setInterval(() => this.poll(src), 1000);
    this.timers.set(src.path, timer);
    this.active.add(src.module);
  }

  private poll(src: LogSource): void {
    let stat;
    try { stat = statSync(src.path); } catch { return; }
    const prev = this.positions.get(src.path) ?? 0;

    if (stat.size < prev) {
      this.positions.set(src.path, 0); // rotated
      return;
    }
    if (stat.size === prev) return;

    const stream = createReadStream(src.path, { start: prev, encoding: 'utf-8' });
    stream.on('error', () => this.positions.set(src.path, stat.size));
    const rl = createInterface({ input: stream });
    rl.on('error', () => {});
    rl.on('line', (line) => {
      if (!line.trim()) return;
      this.process(line, src);
    });
    rl.on('close', () => this.positions.set(src.path, stat.size));
  }

  private process(line: string, src: LogSource): void {
    const parsed = autoDetectParser(line);
    if (!parsed) return;

    let severity: EventSeverity = 'info';
    let message = line;
    let sourceIp: string | undefined;

    if (parsed.source === 'auth') {
      const entry = parseAuthLog(line);
      if (!entry) return;
      sourceIp = entry.fields.ip;
      const msg = entry.fields.message;
      if (/failed password/i.test(msg)) {
        severity = 'high';
        message = `Failed SSH login for ${entry.fields.user || 'unknown'} from ${entry.fields.ip || 'unknown'}`;
      } else if (/invalid user/i.test(msg)) {
        severity = 'high';
        message = `Invalid SSH user: ${entry.fields.user || 'unknown'} from ${entry.fields.ip || 'unknown'}`;
      } else if (/accepted/i.test(msg)) {
        severity = 'info';
        message = `SSH login accepted for ${entry.fields.user || 'unknown'}`;
      } else {
        return;
      }
    } else if (parsed.source === 'nginx') {
      const entry = parseNginxLog(line);
      if (!entry) return;
      sourceIp = entry.fields.ip;
      const status = parseInt(entry.fields.status, 10);
      const attack = detectAttackPattern(entry.fields.path);
      if (attack) {
        severity = 'critical';
        message = `Attack [${attack.toUpperCase()}]: ${entry.fields.method} ${entry.fields.path}`;
      } else if (status >= 500) {
        severity = 'medium';
        message = `Server error ${status}: ${entry.fields.method} ${entry.fields.path}`;
      } else if (status >= 400) {
        severity = 'low';
        message = `Client error ${status}: ${entry.fields.method} ${entry.fields.path}`;
      } else {
        return;
      }
    } else {
      return;
    }

    const event: ThreatEvent = {
      timestamp: new Date(),
      module: src.module,
      category: src.category,
      severity,
      message,
      source_ip: sourceIp,
    };

    try { insertEvent(event); } catch { /* db optional */ }
    this.bus.publish(event);
  }
}
