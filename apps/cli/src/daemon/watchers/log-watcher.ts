import { existsSync, accessSync, constants } from 'node:fs';
import { LogTail } from '../../core/log-tail.js';
import type { EventBus } from '../event-bus.js';
import { assessNginxRequest, attackSeverity, autoDetectParser, classifySshAuth, parseAuthLog, parseNginxLog } from '../../core/log-parser.js';
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
  private tails = new Map<string, LogTail>();
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
    this.tails.clear();
    this.active.clear();
  }

  activeModules(): string[] {
    return [...this.active];
  }

  /**
   * The auth logs being tailed. While there is one, it is the only source of
   * SSH events: sshd's journald records carry the same lines, and counting
   * both would halve every SSH threshold.
   */
  authLogs(): string[] {
    return this.sources.filter((s) => s.category === 'auth' && this.timers.has(s.path)).map((s) => s.path);
  }

  private tail(src: LogSource): void {
    const tail = new LogTail(src.path);
    this.tails.set(src.path, tail);
    const timer = setInterval(() => this.poll(src), 1000);
    this.timers.set(src.path, timer);
    this.active.add(src.module);
  }

  /** Each new line exactly once; see LogTail for why this is synchronous. */
  poll(src: LogSource): number {
    const tail = this.tails.get(src.path);
    if (!tail) return 0;
    return tail.poll((line) => {
      try {
        this.process(line, src);
      } catch {
        // one bad line must not stop the rest
      }
    });
  }

  private process(line: string, src: LogSource): void {
    const parsed = autoDetectParser(line);
    if (!parsed) return;

    let severity: EventSeverity = 'info';
    let message = line;
    let sourceIp: string | undefined;
    const details: Record<string, unknown> = {};

    if (parsed.source === 'auth') {
      const entry = parseAuthLog(line);
      if (!entry) return;
      const verdict = classifySshAuth(entry);
      if (!verdict) return;
      ({ severity, message, source_ip: sourceIp } = verdict);
    } else if (parsed.source === 'nginx') {
      const entry = parseNginxLog(line);
      if (!entry) return;
      sourceIp = entry.fields.ip;
      const status = parseInt(entry.fields.status, 10);
      const crs = assessNginxRequest(entry);
      const attack = attackSeverity(crs);
      const type = (crs.attackType ?? 'unknown').toUpperCase();
      // Present only when the log format carries `$host`. On a box serving one
      // site it adds nothing; on a box serving five it is the difference
      // between "someone is being probed" and knowing which site.
      if (entry.fields.host) details.host = entry.fields.host;
      // The path (without querystring) and UA travel in details so aggregate
      // rules can group by endpoint and a UA rule can match the client — a
      // distributed paywall scrape is invisible per-IP but obvious per-endpoint.
      const reqPath = (entry.fields.path || '').split('?')[0];
      if (reqPath) details.path = reqPath;
      if (entry.fields.user_agent) details.ua = entry.fields.user_agent;
      // How the server answered, and the request as sent. Watchdog mode needs
      // both: a probe that came back 200 is a possible hole, the same probe
      // 404'd is noise — and the querystring is where the payload lives.
      if (Number.isFinite(status)) details.status = status;
      if (entry.fields.method) details.method = entry.fields.method;
      if (entry.fields.path) details.url = entry.fields.path.slice(0, 2048);
      if (crs.score > 0) {
        Object.assign(details, {
          attack_type: crs.attackType,
          crs_score: crs.score,
          crs_threshold: crs.threshold,
          crs_rule_ids: crs.matches.map((m) => m.id),
        });
      }
      if (attack) {
        severity = attack;
        message = `Attack [${type}]: ${entry.fields.method} ${entry.fields.path}`;
      } else if (status >= 500) {
        severity = 'medium';
        message = `Server error ${status}: ${entry.fields.method} ${entry.fields.path}`;
      } else if (status >= 400) {
        severity = 'low';
        message = `Client error ${status}: ${entry.fields.method} ${entry.fields.path}`;
      } else if (crs.score > 0) {
        // Matched, but below the threshold: worth seeing, not worth a ban.
        severity = 'low';
        message = `Suspicious [${type}] (score ${crs.score}/${crs.threshold}): ${entry.fields.method} ${entry.fields.path}`;
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
      ...(Object.keys(details).length ? { details } : {}),
    };

    try { insertEvent(event); } catch { /* db optional */ }
    this.bus.publish(event);
  }
}
