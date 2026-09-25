import { describe, it, expect, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';
import { crawlerVerifier, type Resolver } from '../firewall/crawlers.js';

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

/** A tiny DNS: PTR records and A records. */
function resolver(ptr: Record<string, string[]>, a: Record<string, string[]>): Resolver {
  return {
    reverse: async (ip) => { if (!ptr[ip]) throw new Error('ENOTFOUND'); return ptr[ip]; },
    lookup: async (host) => { if (!a[host]) throw new Error('ENOTFOUND'); return a[host]; },
  };
}

const dns = resolver(
  {
    '66.249.74.136': ['crawl-66-249-74-136.googlebot.com'],
    '157.55.39.1': ['msnbot-157-55-39-1.search.msn.com'],
    // Anyone can set a PTR on their own address. The forward lookup is what
    // they cannot fake.
    '203.0.113.66': ['crawl-66-249-74-136.googlebot.com'],
    '34.1.2.3': ['3.2.1.34.bc.googleusercontent.com'],
  },
  {
    'crawl-66-249-74-136.googlebot.com': ['66.249.74.136'],
    'msnbot-157-55-39-1.search.msn.com': ['157.55.39.1'],
    '3.2.1.34.bc.googleusercontent.com': ['34.1.2.3'],
  },
);

function detection(ip: string): ThreatEvent {
  return {
    timestamp: new Date(),
    module: 'rule-engine',
    category: 'web',
    severity: 'critical',
    message: '[DETECTION] Remote File Inclusion',
    source_ip: ip,
    details: { rule_id: 'rfi', remediation: { action: 'block' } },
  };
}

describe('crawlerVerifier', () => {
  const verify = crawlerVerifier(dns);

  it('verifies Googlebot and Bingbot by forward-confirmed reverse DNS', async () => {
    expect(await verify('66.249.74.136')).toBe('crawl-66-249-74-136.googlebot.com');
    expect(await verify('157.55.39.1')).toBe('msnbot-157-55-39-1.search.msn.com');
  });

  it('rejects a forged PTR whose name does not resolve back', async () => {
    expect(await verify('203.0.113.66')).toBeNull();
  });

  it('does not treat Google Cloud customers as Google', async () => {
    expect(await verify('34.1.2.3')).toBeNull();
  });

  it('treats a DNS failure as unverified', async () => {
    expect(await verify('198.51.100.9')).toBeNull();
  });
});

describe('auto-defence spares verified crawlers', () => {
  const make = (config = {}) => {
    const adapter = new FakeAdapter();
    const manager = new RemediationManager(
      adapter, bus, { protect_current_ssh_client: false, ...config }, crawlerVerifier(dns),
    );
    return { adapter, manager };
  };

  it('does not ban Googlebot, even on a critical detection', async () => {
    const { adapter, manager } = make();
    await manager.handleDetection(detection('66.249.74.136'));
    expect(adapter.blocked.size).toBe(0);
  });

  it('still bans an impostor with a forged PTR', async () => {
    const { adapter, manager } = make();
    await manager.handleDetection(detection('203.0.113.66'));
    expect(adapter.blocked.has('203.0.113.66')).toBe(true);
  });

  it('bans Googlebot when the operator turns sparing off', async () => {
    const { adapter, manager } = make({ spare_verified_crawlers: false });
    await manager.handleDetection(detection('66.249.74.136'));
    expect(adapter.blocked.has('66.249.74.136')).toBe(true);
  });

  it('lets a manual block through', async () => {
    const { adapter, manager } = make();
    const r = await manager.ban('66.249.74.136', 'manual', { source: 'manual' });
    expect(r.ok).toBe(true);
    expect(adapter.blocked.has('66.249.74.136')).toBe(true);
  });
});
