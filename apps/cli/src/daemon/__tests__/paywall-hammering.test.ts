import { describe, it, expect, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { RuleEngine } from '../rules/engine.js';

vi.mock('../../core/state.js', () => ({
  getModuleState: () => undefined,
  setModuleState: () => {},
}));

const { RemediationManager } = await import('../firewall/remediation.js');

class FakeAdapter implements FirewallAdapter {
  name = 'fake';
  enforces = true;
  blocked = new Set<string>();
  isAvailable(): boolean { return true; }
  async block(ip: string): Promise<void> { this.blocked.add(ip); }
  async unblock(ip: string): Promise<void> { this.blocked.delete(ip); }
  async isBlocked(ip: string): Promise<boolean> { return this.blocked.has(ip); }
  async listBlocked(): Promise<string[]> { return [...this.blocked]; }
}

const bus = { publish: () => {}, on: () => {}, announceModule: () => {} } as never;

function hit(ip: string, status = 402): ThreatEvent {
  return {
    timestamp: new Date(),
    module: 'log-watcher',
    category: 'web',
    severity: 'low',
    message: `Client error ${status}: GET /api/v1/search?country=FR&offset=25`,
    source_ip: ip,
    details: { host: 'r4ck.dev' },
  };
}

/** The daemon's wiring, minus the bus: rule engine detections go to remediation. */
function harness() {
  const adapter = new FakeAdapter();
  // No live DNS: no address here is a verified crawler.
  const manager = new RemediationManager(adapter, bus, { protect_current_ssh_client: false }, async () => null);
  const pending: Promise<void>[] = [];
  const engine = new RuleEngine((d) => {
    pending.push(manager.handleDetection({
      timestamp: new Date(),
      module: 'rule-engine',
      category: 'web',
      severity: d.severity,
      message: `[DETECTION] ${d.title}`,
      source_ip: d.source_ip,
      details: { rule_id: d.rule_id, ...d.raw_metadata },
    }));
  });
  engine.loadRules(DEFAULT_RULES);
  return { adapter, manager, engine, settle: () => Promise.all(pending) };
}

describe('paywall-hammering', () => {
  it('is high with a block remediation, so auto-defence can act on it', () => {
    const rule = DEFAULT_RULES.find((r) => r.id === 'paywall-hammering');
    expect(rule?.severity).toBe('high');
    expect(rule?.remediation?.action).toBe('block');
  });

  it('bans a scraper that keeps hitting 402s', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 30; i++) engine.evaluate(hit('45.156.87.133'));
    await settle();
    expect(adapter.blocked.has('45.156.87.133')).toBe(true);
  });

  it('leaves a caller who got a few 402s alone', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 5; i++) engine.evaluate(hit('203.0.113.7'));
    await settle();
    expect(adapter.blocked.size).toBe(0);
  });

  it('never bans a swarm that asks once per address', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 200; i++) engine.evaluate(hit(`198.51.${i >> 8}.${i & 255}`));
    await settle();
    expect(adapter.blocked.size).toBe(0);
  });

  it('does not count other 4xx toward it', async () => {
    const { adapter, engine, settle } = harness();
    // 19 404s stays under web-scanner-detection's 20 too, so nothing else bans.
    for (let i = 0; i < 19; i++) engine.evaluate(hit('203.0.113.8', 404));
    await settle();
    expect(adapter.blocked.size).toBe(0);
  });
});
