import { describe, it, expect, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';

/**
 * dev2 reported "Nothing is banned" while three hosts were still being
 * dropped. Reconcile only ever *added*: if the state DB failed to open, was
 * reset, or the daemon died between writing a rule and saving it, the address
 * stayed blocked with nothing left to explain it or expire it — the
 * unreviewable accretion PRD 0010 is written against.
 */
const state = { saved: undefined as unknown };
vi.mock('../../core/state.js', () => ({
  getModuleState: () => state.saved,
  setModuleState: (_m: string, _k: string, v: unknown) => { state.saved = v; },
}));

const { RemediationManager } = await import('../firewall/remediation.js');

class FakeAdapter implements FirewallAdapter {
  name = 'fake';
  enforces = true;
  constructor(public blocked = new Set<string>()) {}
  isAvailable(): boolean { return true; }
  async block(ip: string): Promise<void> { this.blocked.add(ip); }
  async unblock(ip: string): Promise<void> { this.blocked.delete(ip); }
  async isBlocked(ip: string): Promise<boolean> { return this.blocked.has(ip); }
  async listBlocked(): Promise<string[]> { return [...this.blocked]; }
}

const bus = { publish: () => {}, on: () => {}, announceModule: () => {} } as never;
const settle = () => new Promise((r) => setTimeout(r, 20));

describe('reconcile prunes rules it cannot account for', () => {
  it('removes a firewall entry with no record in state', async () => {
    state.saved = undefined; // state DB empty — the dev2 situation
    const adapter = new FakeAdapter(new Set(['67.205.189.229', '134.199.185.111']));

    new RemediationManager(adapter, bus, { protect_current_ssh_client: false });
    await settle();

    expect([...adapter.blocked]).toEqual([]);
  });

  it('keeps an entry that state still explains', async () => {
    const future = Date.now() + 600_000;
    state.saved = [{
      ip: '45.33.22.11',
      reason: 'Failed SSH login',
      blocked_at: Date.now(),
      expires_at: future,
      dry_run: false,
      strikes: 2,
      source: 'auto',
    }];
    const adapter = new FakeAdapter(new Set(['45.33.22.11', '8.8.8.8']));

    new RemediationManager(adapter, bus, { protect_current_ssh_client: false });
    await settle();

    // The explained ban stays; the orphan goes.
    expect([...adapter.blocked]).toEqual(['45.33.22.11']);
  });

  it('prunes even in dry-run', async () => {
    // A daemon insisting it changes nothing must not leave yesterday's
    // enforcement standing.
    state.saved = undefined;
    const adapter = new FakeAdapter(new Set(['67.205.189.229']));

    new RemediationManager(adapter, bus, { dry_run: true, protect_current_ssh_client: false });
    await settle();

    expect([...adapter.blocked]).toEqual([]);
  });
});
