import { describe, it, expect, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';

// A state DB written by an older release: one ban on a Cloudflare edge (now
// protected) and one on a real attacker, both still within their ban time.
const future = Date.now() + 3_600_000;
const saved = [
  { ip: '172.68.229.144', reason: 'old ban', blocked_at: Date.now(), expires_at: future, dry_run: false, strikes: 1, source: 'auto' },
  { ip: '45.148.10.7', reason: 'probe', blocked_at: Date.now(), expires_at: future, dry_run: false, strikes: 1, source: 'auto' },
];
vi.mock('../../core/state.js', () => ({
  getModuleState: (_m: string, key: string) => (key === 'blocklist' ? saved : undefined),
  setModuleState: () => {},
}));

const { RemediationManager } = await import('../firewall/remediation.js');

class FakeAdapter implements FirewallAdapter {
  name = 'fake';
  enforces = true;
  blocked = new Set<string>(['172.68.229.144', '45.148.10.7']);
  isAvailable(): boolean { return true; }
  async block(ip: string): Promise<void> { this.blocked.add(ip); }
  async unblock(ip: string): Promise<void> { this.blocked.delete(ip); }
  async isBlocked(ip: string): Promise<boolean> { return this.blocked.has(ip); }
  async listBlocked(): Promise<string[]> { return [...this.blocked]; }
}

describe('RemediationManager start-up reconcile', () => {
  it('lifts a ban recorded on an address that is now protected, and keeps the rest', async () => {
    const adapter = new FakeAdapter();
    const bus = { publish: () => {}, on: () => {}, announceModule: () => {} } as never;
    const manager = new RemediationManager(adapter, bus, { protect_current_ssh_client: false });
    await vi.waitFor(() => expect(adapter.blocked.has('172.68.229.144')).toBe(false));
    expect(adapter.blocked.has('45.148.10.7')).toBe(true);
    expect(manager.getBlocklist().map((b) => b.ip)).toEqual(['45.148.10.7']);
  });
});
