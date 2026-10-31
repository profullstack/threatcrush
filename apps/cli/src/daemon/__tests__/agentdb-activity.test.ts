import { describe, it, expect, vi } from 'vitest';
import type { EventBus } from '../event-bus.js';
import type { ThreatEvent } from '../../types/events.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { RuleEngine } from '../rules/engine.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const { LogWatcher } = await import('../watchers/log-watcher.js');
const SOURCE = { path: '/var/log/nginx/access.log', module: 'log-watcher', category: 'web' as const };
const CADDY_SOURCE = { path: '/var/log/caddy/agent.database.pit.world.access.log', module: 'log-watcher', category: 'web' as const };

function daemonEvent(
  status: number,
  bytes: number,
  host = 'agent.database.pit.world',
  requestPath = '/v1/query_readonly',
): ThreatEvent | undefined {
  let published: ThreatEvent | undefined;
  const bus = { publish: (event: ThreatEvent) => { published = event; } } as unknown as EventBus;
  const watcher = new LogWatcher(bus, []) as unknown as { process(line: string, src: typeof SOURCE): void };
  watcher.process(
    `${host} 203.0.113.9 - - [31/Oct/2026:09:19:29 +0000] "POST ${requestPath} HTTP/1.1" ${status} ${bytes} "-" "agent-test"`,
    SOURCE,
  );
  return published;
}

function firedRules(event: ThreatEvent, count = 1): string[] {
  const fired: string[] = [];
  const engine = new RuleEngine((detection) => fired.push(detection.rule_id));
  engine.loadRules(DEFAULT_RULES);
  for (let index = 0; index < count; index++) engine.evaluate(event);
  return fired;
}

function firedRulesForEvents(events: ThreatEvent[]): string[] {
  const fired: string[] = [];
  const engine = new RuleEngine((detection) => fired.push(detection.rule_id));
  engine.loadRules(DEFAULT_RULES);
  for (const event of events) engine.evaluate(event);
  return fired;
}

describe('AgentDB activity detection from reverse-proxy access logs', () => {
  it('records only API path and response size as AgentDB context', () => {
    const event = daemonEvent(200, 1_040_000)!;
    expect(event.details).toMatchObject({
      service: 'agentdb',
      path: '/v1/query_readonly',
      status: 200,
      response_bytes: 1_040_000,
    });
    expect(event.details?.url).toBe('/v1/query_readonly');
    expect(firedRules(event, 3)).toContain('agentdb-large-query-exports');
  });

  it('strips query parameters before storing an AgentDB request in an alert', () => {
    const event = daemonEvent(200, 500, 'agent.database.pit.world', '/v1/query_readonly?access_token=do-not-copy')!;
    expect(JSON.stringify(event)).not.toContain('do-not-copy');
    expect(event.details?.url).toBe('/v1/query_readonly');
  });

  it('alerts on rejected credential bursts and query bursts without auto-banning the source', () => {
    expect(firedRules(daemonEvent(401, 180)!, 5)).toContain('agentdb-auth-failure-burst');
    const burst = firedRules(daemonEvent(200, 600)!, 60);
    expect(burst).toContain('agentdb-query-burst');
    expect(DEFAULT_RULES.find((rule) => rule.id === 'agentdb-query-burst')?.remediation?.action).toBe('alert');
  });

  it('detects a query burst distributed across source addresses', () => {
    const events = Array.from({ length: 60 }, (_, index) => {
      const event = daemonEvent(200, 600)!;
      event.source_ip = `192.0.2.${(index % 254) + 1}`;
      return event;
    });
    expect(firedRulesForEvents(events)).toContain('agentdb-query-burst');
  });

  it('alerts when an operator creates several service tokens in a minute', () => {
    const creation = daemonEvent(200, 320, 'agent.database.pit.world', '/v1/tokens')!;
    expect(firedRules(creation, 3)).toContain('agentdb-token-creation-burst');
  });

  it('alerts when the read quota returns HTTP 429', () => {
    expect(firedRules(daemonEvent(429, 210)!)).toContain('agentdb-query-throttled');
  });

  it('does not label a similarly shaped API on another virtual host as AgentDB', () => {
    expect(daemonEvent(200, 600, 'other.example')).toBeUndefined();
  });

  it('reads Caddy JSON access records for the production AgentDB vhost', () => {
    let published: ThreatEvent | undefined;
    const bus = { publish: (event: ThreatEvent) => { published = event; } } as unknown as EventBus;
    const watcher = new LogWatcher(bus, []) as unknown as { process(line: string, src: typeof CADDY_SOURCE): void };
    watcher.process(JSON.stringify({
      level: 'info', ts: 1793438369, logger: 'http.log.access.log0', msg: 'handled request',
      request: { remote_ip: '203.0.113.9', method: 'POST', host: 'agent.database.pit.world', uri: '/v1/query_readonly', proto: 'HTTP/2.0' },
      status: 200, size: 1_040_000,
    }), CADDY_SOURCE);
    expect(published).toMatchObject({
      module: 'log-watcher', source_ip: '203.0.113.9',
      details: { service: 'agentdb', path: '/v1/query_readonly', status: 200, response_bytes: 1_040_000 },
    });
    expect(firedRules(published!, 3)).toContain('agentdb-large-query-exports');
  });

  it('keeps query parameters out of AgentDB Caddy events', () => {
    let published: ThreatEvent | undefined;
    const bus = { publish: (event: ThreatEvent) => { published = event; } } as unknown as EventBus;
    const watcher = new LogWatcher(bus, []) as unknown as { process(line: string, src: typeof CADDY_SOURCE): void };
    watcher.process(JSON.stringify({
      logger: 'http.log.access.log0',
      request: { remote_ip: '203.0.113.9', method: 'POST', host: 'agent.database.pit.world', uri: '/v1/query_readonly?access_token=do-not-copy' },
      status: 200, size: 500,
    }), CADDY_SOURCE);
    expect(JSON.stringify(published)).not.toContain('do-not-copy');
    expect(published?.details?.url).toBe('/v1/query_readonly');
  });
});
