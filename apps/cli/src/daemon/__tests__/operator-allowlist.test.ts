import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';

const store = new Map<string, unknown>();
vi.mock('../../core/state.js', () => ({
  getModuleState: (m: string, k: string) => store.get(`${m}/${k}`),
  setModuleState: (m: string, k: string, v: unknown) => { store.set(`${m}/${k}`, JSON.parse(JSON.stringify(v))); },
}));

const { RemediationManager } = await import('../firewall/remediation.js');
const { isAutomationKeyComment, moshClients, parseKeyLogins, sshClientFromEnviron } = await import('../firewall/protected.js');

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
const nowSec = () => Date.now() / 1000;

const attack = (ip: string): ThreatEvent => ({
  timestamp: new Date(), module: 'rule-engine', category: 'web', severity: 'critical',
  message: '[DETECTION] SQL injection', source_ip: ip, details: { rule_id: 'web-sqli-attack' },
});

function make(adapter: FakeAdapter, discovery: Partial<{ sshPeers: string[]; mosh: string[]; journal: string; automation: string[] }> = {}) {
  return new RemediationManager(adapter, bus, {}, async () => null, {
    sshPeers: () => discovery.sshPeers ?? [],
    moshClients: () => discovery.mosh ?? [],
    keyLoginJournal: async () => discovery.journal ?? '',
    automationKeys: () => new Set(discovery.automation ?? []),
  });
}

describe('parsers', () => {
  it('tells automation keys from people by their comment', () => {
    expect(['github-actions-deploy@crawlproof', 'seed-backup-pull@seed.h4kr.com', 'ci runner', 'ettinger@wiley', 'anthony@laptop']
      .map(isAutomationKeyComment)).toEqual([true, true, true, false, false]);
  });

  it('reads key logins with their newest time, and skips password logins', () => {
    const t = nowSec();
    const logins = parseKeyLogins([
      `${t - 100} dev2 sshd-session[1]: Accepted publickey for root from 104.152.209.195 port 59510 ssh2: ED25519 SHA256:x`,
      `${t - 10} dev2 sshd-session[2]: Accepted publickey for root from 104.152.209.195 port 59511 ssh2: ED25519 SHA256:x`,
      `${t - 5} dev2 sshd-session[3]: Accepted password for root from 198.51.100.66 port 4000 ssh2`,
      `${t - 5} dev2 sshd-session[4]: Failed password for root from 203.0.113.9 port 4000 ssh2`,
    ].join('\n'));
    expect([...logins.keys()]).toEqual(['104.152.209.195']);
    expect(logins.get('104.152.209.195')).toBe(Math.round((t - 10) * 1000));
  });

  it("finds a mosh session's origin in mosh-server's environment", () => {
    expect(sshClientFromEnviron('HOME=/root\0SSH_CONNECTION=203.0.113.7 51000 10.0.0.2 22\0LANG=C')).toBe('203.0.113.7');
    const proc = mkdtempSync(join(tmpdir(), 'tc-proc-'));
    const pid = (n: string, comm: string, env: string) => {
      mkdirSync(join(proc, n));
      writeFileSync(join(proc, n, 'comm'), `${comm}\n`);
      writeFileSync(join(proc, n, 'environ'), env);
    };
    pid('100', 'mosh-server', 'SSH_CLIENT=203.0.113.7 51000 22\0');
    pid('101', 'bash', 'SSH_CLIENT=198.51.100.1 1 22\0');
    pid('102', 'mosh-server', 'PATH=/bin\0'); // started some other way: nothing to learn
    expect(moshClients(proc)).toEqual(['203.0.113.7']);
  });
});

describe('remembered operator addresses', () => {
  let adapter: FakeAdapter;
  beforeEach(() => { adapter = new FakeAdapter(); store.clear(); });

  it('a key login from the journal protects that address and lifts a ban already on it', async () => {
    store.set('firewall-rules/blocklist', [{ ip: '104.152.209.195', blocked_at: Date.now(), expires_at: Date.now() + 3600_000, strikes: 1, source: 'auto' }]);
    adapter.blocked.add('104.152.209.195');
    const m = make(adapter, { journal: `${nowSec() - 3600} dev2 sshd-session[1]: Accepted publickey for root from 104.152.209.195 port 1 ssh2` });
    await m.seedOperatorsFromJournal();
    await new Promise((r) => setTimeout(r, 0));
    expect(m.isAllowlisted('104.152.209.195')).toBe(true);
    expect(adapter.blocked.has('104.152.209.195')).toBe(false);
    await m.handleDetection(attack('104.152.209.195'));
    expect(adapter.blocked.size).toBe(0);
    m.stop();
  });

  it('a login older than the memory does not count', async () => {
    const m = make(adapter, { journal: `${nowSec() - 40 * 86400} dev2 sshd-session[1]: Accepted publickey for root from 198.51.100.4 port 1 ssh2` });
    await m.seedOperatorsFromJournal();
    expect(m.isAllowlisted('198.51.100.4')).toBe(false);
    m.stop();
  });

  it('remembers a live mosh client across a restart', async () => {
    const first = make(adapter, { mosh: ['203.0.113.7'] });
    expect(first.getOperators()).toHaveProperty(['203.0.113.7']);
    first.stop();
    const second = make(adapter); // no session now, nothing in the journal
    expect(second.isAllowlisted('203.0.113.7')).toBe(true);
    await second.handleDetection(attack('203.0.113.7'));
    expect(adapter.blocked.size).toBe(0);
    second.stop();
  });

  it("never remembers a CI deploy key's runner address", async () => {
    const t = nowSec() - 60;
    const m = make(adapter, {
      automation: ['SHA256:ciKey'],
      journal: [
        `${t} dev2 sshd-session[1]: Accepted publickey for anthony from 13.78.166.244 port 56320 ssh2: ED25519 SHA256:ciKey`,
        `${t} dev2 sshd-session[2]: Accepted publickey for anthony from 172.12.140.170 port 57965 ssh2: ED25519 SHA256:laptop`,
      ].join('\n'),
    });
    await m.seedOperatorsFromJournal();
    expect(Object.keys(m.getOperators())).toEqual(['172.12.140.170']);
    expect(m.isAllowlisted('13.78.166.244')).toBe(false);
    m.stop();
  });

  it('protects a live SSH peer while connected but does not remember it', () => {
    const first = make(adapter, { sshPeers: ['198.51.100.20'] });
    expect(first.isAllowlisted('198.51.100.20')).toBe(true);
    expect(first.getOperators()).toEqual({});
    first.stop();
    const second = make(adapter);
    expect(second.isAllowlisted('198.51.100.20')).toBe(false);
    second.stop();
  });

  it('can be turned off', async () => {
    const m = new RemediationManager(adapter, bus, { protect_recent_operators: false }, async () => null, {
      sshPeers: () => [], moshClients: () => [], automationKeys: () => new Set(),
      keyLoginJournal: async () => `${nowSec()} h sshd-session[1]: Accepted publickey for root from 198.51.100.8 port 1 ssh2`,
    });
    await m.seedOperatorsFromJournal();
    expect(m.getOperators()).toEqual({});
    m.stop();
  });
});
