import { describe, it, expect, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { RuleEngine } from '../rules/engine.js';
import { CRAWLER_DOMAINS } from '../firewall/crawlers.js';

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

const DATAFORSEO = 'Mozilla/5.0 (compatible; DataForSeoBot/1.0; +https://dataforseo.com/dataforseo-bot)';
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36';

/** A 402 from `ip`, `secondsAgo` before `base`, as log-watcher reports it. */
function hit(ip: string, ua: string, at: Date, status = 402): ThreatEvent {
  return {
    timestamp: at,
    module: 'log-watcher',
    category: 'web',
    severity: 'low',
    message: `Client error ${status}: GET /events/136398`,
    source_ip: ip,
    details: { host: 'watchnews.now', path: '/events/136398', ua },
  };
}

/** The daemon's wiring: detections go to remediation. `verified` maps an IP to a crawler hostname. */
function harness(verified: Record<string, string> = {}) {
  const adapter = new FakeAdapter();
  const manager = new RemediationManager(
    adapter,
    bus,
    { protect_current_ssh_client: false },
    async (ip: string) => verified[ip] ?? null,
  );
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
  return { adapter, engine, settle: () => Promise.all(pending) };
}

/** `n` hits spread evenly over `minutes`, ending now. */
function paced(n: number, minutes: number): Date[] {
  const now = Date.now();
  return Array.from({ length: n }, (_, i) => new Date(now - (minutes * 60_000 * (n - 1 - i)) / n));
}

describe('paywall-ignored', () => {
  it('is high with a block remediation', () => {
    const rule = DEFAULT_RULES.find((r) => r.id === 'paywall-ignored');
    expect(rule?.severity).toBe('high');
    expect(rule?.remediation?.action).toBe('block');
  });

  it('bans a browser-looking caller that keeps walking the paywall slowly (under paywall-hammering)', async () => {
    vi.useFakeTimers({ now: Date.now() });
    const { adapter, engine, settle } = harness();
    // 20 402s over 9 minutes: ~2 a minute, nowhere near 30 in 60s.
    for (const at of paced(20, 9)) {
      vi.setSystemTime(at);
      engine.evaluate(hit('198.51.100.20', CHROME, at));
    }
    await settle();
    vi.useRealTimers();
    expect(adapter.blocked.has('198.51.100.20')).toBe(true);
  });

  it('leaves a person who got a few 402s alone', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 4; i++) engine.evaluate(hit('203.0.113.7', CHROME, new Date()));
    await settle();
    expect(adapter.blocked.size).toBe(0);
  });

  it('never bans a swarm that asks once per address, or on generic 4xx', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 300; i++) engine.evaluate(hit(`198.51.${i >> 8}.${i & 255}`, CHROME, new Date()));
    for (let i = 0; i < 19; i++) engine.evaluate(hit('203.0.113.9', CHROME, new Date(), 404));
    await settle();
    expect(adapter.blocked.size).toBe(0);
  });

  it('never bans a verified search crawler, however many 402s it took', async () => {
    const { adapter, engine, settle } = harness({ '66.249.73.129': 'crawl-66-249-73-129.googlebot.com' });
    const googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    for (let i = 0; i < 40; i++) engine.evaluate(hit('66.249.73.129', googlebot, new Date()));
    await settle();
    expect(adapter.blocked.size).toBe(0);
  });
});

describe('paywall-declared-scraper', () => {
  it('bans a declared SEO scraper on its fifth 402 in five minutes', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 5; i++) engine.evaluate(hit('136.243.1.9', DATAFORSEO, new Date()));
    await settle();
    expect(adapter.blocked.has('136.243.1.9')).toBe(true);
  });

  it('bans Lightpanda the same way, and not at four', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 5; i++) engine.evaluate(hit('49.43.1.1', 'Lightpanda/1.0', new Date()));
    for (let i = 0; i < 4; i++) engine.evaluate(hit('49.43.1.2', 'Lightpanda/1.0', new Date()));
    await settle();
    expect([...adapter.blocked]).toEqual(['49.43.1.1']);
  });

  it('does not match a browser or a search crawler', async () => {
    const { adapter, engine, settle } = harness();
    for (let i = 0; i < 5; i++) engine.evaluate(hit('203.0.113.10', CHROME, new Date()));
    for (let i = 0; i < 5; i++) {
      engine.evaluate(hit('203.0.113.11', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', new Date()));
    }
    await settle();
    expect(adapter.blocked.size).toBe(0);
  });
});

describe('verified crawlers', () => {
  it('include Applebot', () => {
    expect(CRAWLER_DOMAINS).toContain('applebot.apple.com');
  });
});
