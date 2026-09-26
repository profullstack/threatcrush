import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';
import { fakeCloud, isolateHome, type FakeReply } from './helpers/fake-cloud.js';

vi.mock('../../core/state.js', () => ({
  getModuleState: () => undefined,
  setModuleState: () => {},
}));

// Imported after isolateHome(): cli-config and paths fix ~/.threatcrush at load time.
isolateHome();
const { writeCliConfig } = await import('../../core/cli-config.js');
const { RemediationManager } = await import('../firewall/remediation.js');
const { RemediationConsumer } = await import('../workers/remediation-consumer.js');
const { AllowlistSync } = await import('../workers/allowlist-sync.js');

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

function setup(config: Record<string, unknown> = {}) {
  const adapter = new FakeAdapter();
  const published: ThreatEvent[] = [];
  const bus = { publish: (e: ThreatEvent) => published.push(e), on: () => {}, announceModule: () => {} } as never;
  const manager = new RemediationManager(adapter, bus, {
    protect_current_ssh_client: false,
    spare_verified_crawlers: false,
    ...config,
  });
  const logs: string[] = [];
  return { adapter, manager, published, logs, log: (l: string) => logs.push(l) };
}

const action = (over: Record<string, unknown>) => ({
  id: 'act-1',
  action_type: 'block',
  target_value: '203.0.113.9',
  expires_at: null,
  metadata: {},
  created_at: '2026-09-25T12:00:00Z',
  ...over,
});

beforeEach(() => {
  writeCliConfig({ token: 'tok', refresh_token: 'r1', server_id: 'srv-1', server_org_id: 'org-1' });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('remediation consumer', () => {
  it('claims, blocks through the manager, and PATCHes executed', async () => {
    const { adapter, manager, published, log } = setup();
    let claimed = false;
    const cloud = fakeCloud((req): FakeReply => {
      if (req.path.endsWith('/remediations/claim')) {
        const actions = claimed ? [] : [action({ expires_at: new Date(Date.now() + 600_000).toISOString() })];
        claimed = true;
        return { status: 200, body: { actions } };
      }
      return { status: 200, body: { action: {} } };
    });

    await new RemediationConsumer(manager, { log }).tick();

    expect(cloud.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      'POST /api/orgs/org-1/servers/srv-1/remediations/claim',
      'PATCH /api/orgs/org-1/remediations/act-1',
    ]);
    expect(cloud.requests[1].body).toMatchObject({ status: 'executed', dry_run: false });
    expect(adapter.blocked.has('203.0.113.9')).toBe(true);
    const entry = manager.getBlocklist()[0];
    // The dashboard's expiry, not the one-minute rung of the ladder.
    expect(entry.expires_at - entry.blocked_at).toBeGreaterThan(590_000);
    // The dashboard already has this row; the ban event must not create a second.
    expect(published.find((e) => e.details?.action === 'block')?.details?.origin).toBe('cloud');
  });

  it('refuses to block an allowlisted address and reports failed with the reason', async () => {
    const { adapter, manager, log } = setup({ allowlist: ['198.51.100.0/24'] });
    const result = await new RemediationConsumer(manager, { log })
      .execute(action({ target_value: '198.51.100.7' }));
    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/protected/);
    expect(adapter.blocked.size).toBe(0);
  });

  it('refuses a built-in protected address', async () => {
    const { manager, log } = setup();
    const result = await new RemediationConsumer(manager, { log }).execute(action({ target_value: '10.1.2.3' }));
    expect(result.status).toBe('failed');
  });

  it('in dry-run reports executed with dry_run and touches no firewall', async () => {
    const { adapter, manager, log } = setup({ dry_run: true });
    const result = await new RemediationConsumer(manager, { log }).execute(action({}));
    expect(result).toMatchObject({ status: 'executed', dry_run: true });
    expect(adapter.blocked.size).toBe(0);
    expect(manager.getBlocklist()[0]).toMatchObject({ ip: '203.0.113.9', dry_run: true });
  });

  it('with no expiry bans for the configured maximum', async () => {
    const { manager, log } = setup({ max_ban_seconds: 7200 });
    await new RemediationConsumer(manager, { log }).execute(action({ expires_at: null }));
    const entry = manager.getBlocklist()[0];
    expect(entry.expires_at - entry.blocked_at).toBe(7_200_000);
  });

  it('fails an action whose expiry has already passed', async () => {
    const { adapter, manager, log } = setup();
    const result = await new RemediationConsumer(manager, { log })
      .execute(action({ expires_at: '2020-01-01T00:00:00Z' }));
    expect(result.status).toBe('failed');
    expect(adapter.blocked.size).toBe(0);
  });

  it('unblocks a ban, and treats an address that is not banned as done', async () => {
    const { adapter, manager, log } = setup();
    await manager.ban('203.0.113.9', 'test');
    const consumer = new RemediationConsumer(manager, { log });
    expect(await consumer.execute(action({ action_type: 'unblock' }))).toMatchObject({ status: 'executed' });
    expect(adapter.blocked.has('203.0.113.9')).toBe(false);
    expect(await consumer.execute(action({ action_type: 'unblock' }))).toMatchObject({ status: 'executed' });
  });

  it('adds and removes allowlist entries but never a built-in range', async () => {
    const { manager, log } = setup();
    const consumer = new RemediationConsumer(manager, { log });
    expect(await consumer.execute(action({ action_type: 'allowlist_add', target_value: '203.0.113.0/24' })))
      .toMatchObject({ status: 'executed' });
    expect(manager.isAllowlisted('203.0.113.9')).toBe(true);
    await consumer.execute(action({ action_type: 'allowlist_remove', target_value: '203.0.113.0/24' }));
    expect(manager.isAllowlisted('203.0.113.9')).toBe(false);

    expect(await consumer.execute(action({ action_type: 'allowlist_remove', target_value: '10.0.0.0/8' })))
      .toMatchObject({ status: 'failed' });
    expect(manager.isAllowlisted('10.1.2.3')).toBe(true);
    expect(await consumer.execute(action({ action_type: 'allowlist_add', target_value: 'not-an-ip' })))
      .toMatchObject({ status: 'failed' });
  });

  it('retries a PATCH the dashboard did not take, without executing again', async () => {
    const { manager, log } = setup();
    let patchUp = false;
    let claims = 0;
    const cloud = fakeCloud((req): FakeReply => {
      if (req.path.endsWith('/claim')) return { status: 200, body: { actions: claims++ === 0 ? [action({})] : [] } };
      return patchUp ? { status: 200, body: {} } : 'network-down';
    });
    const consumer = new RemediationConsumer(manager, { log });
    await consumer.tick();
    patchUp = true;
    await consumer.tick();
    await consumer.tick();

    const patches = cloud.requests.filter((r) => r.method === 'PATCH');
    expect(patches).toHaveLength(2);
    expect(patches[1].body).toMatchObject({ status: 'executed' });
    expect(manager.getBlocklist()).toHaveLength(1);
  });
});

describe('org allowlist sync', () => {
  const entries = (...values: Array<[string, string]>) => ({
    status: 200,
    body: { entries: values.map(([type, value]) => ({ type, value })) },
  });

  it('merges org IPs and CIDRs, then removes only what it added', async () => {
    const { manager, log } = setup({ allowlist: ['192.0.2.1'] });
    let reply = entries(['ip', '203.0.113.9'], ['cidr', '198.51.100.0/24'], ['user', 'root'], ['ip', 'nonsense'],
      ['ip', '192.0.2.1'], ['cidr', '10.0.0.0/8']);
    fakeCloud(() => reply);
    const sync = new AllowlistSync(manager, { log });

    await sync.sync();
    expect(manager.isAllowlisted('203.0.113.9')).toBe(true);
    expect(manager.isAllowlisted('198.51.100.20')).toBe(true);

    // Everything gone from the org list.
    reply = entries();
    await sync.sync();
    expect(manager.isAllowlisted('203.0.113.9')).toBe(false);
    expect(manager.isAllowlisted('198.51.100.20')).toBe(false);
    // Built-ins and the operator's own entries survive their removal from the org list.
    expect(manager.isAllowlisted('10.1.2.3')).toBe(true);
    expect(manager.isAllowlisted('127.0.0.1')).toBe(true);
    expect(manager.isAllowlisted('192.0.2.1')).toBe(true);
  });

  it('keeps the current set when the dashboard cannot be reached', async () => {
    const { manager, log } = setup();
    let down = false;
    fakeCloud(() => (down ? 'network-down' : entries(['ip', '203.0.113.9'])));
    const sync = new AllowlistSync(manager, { log });
    await sync.sync();
    down = true;
    await sync.sync();
    expect(manager.isAllowlisted('203.0.113.9')).toBe(true);
  });
});
