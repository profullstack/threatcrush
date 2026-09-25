import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';

// The manager persists through the state DB and appends to the daemon log;
// neither exists in a unit test, and both are best-effort by design.
vi.mock('../../core/state.js', () => ({
  getModuleState: () => undefined,
  setModuleState: () => {},
}));

const { RemediationManager } = await import('../firewall/remediation.js');

class FakeAdapter implements FirewallAdapter {
  name = 'fake';
  enforces = true;
  blocked = new Set<string>();
  failNext = false;

  isAvailable(): boolean { return true; }
  async block(ip: string): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error('EACCES');
    }
    this.blocked.add(ip);
  }
  async unblock(ip: string): Promise<void> { this.blocked.delete(ip); }
  async isBlocked(ip: string): Promise<boolean> { return this.blocked.has(ip); }
  async listBlocked(): Promise<string[]> { return [...this.blocked]; }
}

function fakeBus() {
  const published: ThreatEvent[] = [];
  return {
    published,
    publish: (event: ThreatEvent) => { published.push(event); },
    on: () => {},
    announceModule: () => {},
  } as never;
}

function detection(ip: string, severity: ThreatEvent['severity'] = 'high'): ThreatEvent {
  return {
    timestamp: new Date(),
    module: 'ssh-guard',
    category: 'auth',
    severity,
    message: `Failed SSH login from ${ip}`,
    source_ip: ip,
  };
}

describe('RemediationManager', () => {
  let adapter: FakeAdapter;

  beforeEach(() => {
    adapter = new FakeAdapter();
  });

  const make = (config = {}) =>
    new RemediationManager(adapter, fakeBus(), {
      protect_current_ssh_client: false,
      ...config,
    });

  it('enforces by default rather than only describing what it would do', async () => {
    const manager = make();
    expect(manager.status().dry_run).toBe(false);

    await manager.handleDetection(detection('45.33.22.11'));
    expect(adapter.blocked.has('45.33.22.11')).toBe(true);
  });

  it('bans for one minute on the first offence', async () => {
    const manager = make();
    await manager.handleDetection(detection('45.33.22.11'));

    const [entry] = manager.getBlocklist();
    expect(entry.strikes).toBe(1);
    expect(Math.round((entry.expires_at - entry.blocked_at) / 1000)).toBe(60);
  });

  it('climbs the Fibonacci ladder across repeat offences', async () => {
    const manager = make();
    const lengths: number[] = [];

    for (let i = 0; i < 5; i++) {
      await manager.handleDetection(detection('45.33.22.11'));
      const entry = manager.getBlocklist().find((b) => b.ip === '45.33.22.11');
      if (!entry) throw new Error('expected a ban');
      lengths.push(Math.round((entry.expires_at - entry.blocked_at) / 1000));
      // The address re-offends only after its ban has been lifted.
      await manager.unban('45.33.22.11');
    }

    expect(lengths).toEqual([60, 120, 180, 300, 480]);
  });

  it('ignores anything below the severity floor', async () => {
    const manager = make();
    // The 402s on rssamplifier.com are `low`: thousands of them, all legitimate
    // agent traffic hitting a paywall.
    await manager.handleDetection(detection('45.33.22.11', 'low'));
    expect(manager.getBlocklist()).toHaveLength(0);
  });

  it('never bans a protected address, whatever the detector says', async () => {
    const manager = make();
    for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '::1']) {
      await manager.handleDetection(detection(ip, 'critical'));
    }
    expect(manager.getBlocklist()).toHaveLength(0);
    expect(adapter.blocked.size).toBe(0);
  });

  it('refuses a manual ban on a protected address with a reason', async () => {
    const manager = make();
    const result = await manager.ban('127.0.0.1', 'operator');
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/protected/);
  });

  it('protects the operator additions from the config', async () => {
    const manager = make({ allowlist: ['203.0.113.0/24'] });
    await manager.handleDetection(detection('203.0.113.7', 'critical'));
    expect(manager.getBlocklist()).toHaveLength(0);
  });

  it('does not re-ban an address that is already contained', async () => {
    const manager = make();
    await manager.handleDetection(detection('45.33.22.11'));
    await manager.handleDetection(detection('45.33.22.11'));
    expect(manager.getBlocklist()).toHaveLength(1);
    expect(manager.getBlocklist()[0].strikes).toBe(1);
  });

  it('honours an explicit TTL for a manual ban', async () => {
    const manager = make();
    const result = await manager.ban('45.33.22.11', 'operator', { ttlSeconds: 7200 });
    expect(result.ok).toBe(true);
    expect(Math.round((result.entry!.expires_at - result.entry!.blocked_at) / 1000)).toBe(7200);
  });

  it('clears the strike history when an operator unbans by hand', async () => {
    const manager = make();
    await manager.handleDetection(detection('45.33.22.11'));
    await manager.unban('45.33.22.11', { forget: true });

    // Overruled, so the next offence starts at one minute again rather than two.
    await manager.handleDetection(detection('45.33.22.11'));
    expect(manager.getBlocklist()[0].strikes).toBe(1);
  });

  it('reports a backend failure instead of claiming a ban', async () => {
    const manager = make();
    adapter.failNext = true;
    const result = await manager.ban('45.33.22.11', 'operator');
    expect(result.ok).toBe(false);
    expect(manager.getBlocklist()).toHaveLength(0);
  });

  it('writes no rules in dry-run but still tracks what it would have done', async () => {
    const manager = make({ dry_run: true });
    await manager.handleDetection(detection('45.33.22.11'));
    expect(adapter.blocked.size).toBe(0);
    expect(manager.getBlocklist()).toHaveLength(1);
    expect(manager.getBlocklist()[0].dry_run).toBe(true);
  });

  it('falls back to dry-run when the backend cannot enforce', async () => {
    const powerless = new FakeAdapter();
    powerless.enforces = false;
    const manager = new RemediationManager(powerless, fakeBus(), { protect_current_ssh_client: false });
    expect(manager.status().dry_run).toBe(true);
  });

  it('unbans everything on flush', async () => {
    const manager = make();
    await manager.handleDetection(detection('45.33.22.11'));
    await manager.handleDetection(detection('185.220.101.44'));
    expect(await manager.flush()).toBe(2);
    expect(manager.getBlocklist()).toHaveLength(0);
    expect(adapter.blocked.size).toBe(0);
  });

  it('can be turned off entirely', async () => {
    const manager = make({ enabled: false });
    await manager.handleDetection(detection('45.33.22.11', 'critical'));
    expect(manager.getBlocklist()).toHaveLength(0);
  });
});
