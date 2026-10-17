import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RESOLVER_HOOKS, hostsBlocklist, unboundBlocklist, type FeedSet } from '../threat-feeds/index.js';
import { ThreatFeeds, threatFeedSettings } from '../../daemon/workers/threat-feeds.js';
import { apparmorRule, hookContent, installHook, removeHook, type ResolverIO } from '../../commands/feeds-resolver.js';

describe('resolver blocklist formats', () => {
  it('hosts: both families per name, so AAAA is answered locally too', () => {
    expect(hostsBlocklist(['bad.example']).split('\n').slice(1, 3)).toEqual(['0.0.0.0 bad.example', ':: bad.example']);
  });
  it('unbound: one always_nxdomain zone per name, under server:', () => {
    expect(unboundBlocklist(['bad.example']).split('\n').slice(1, 3)).toEqual(['server:', '  local-zone: "bad.example." always_nxdomain']);
  });
});

const SET: FeedSet = {
  fetched_at: '2026-10-17T00:00:00Z', sources: [], skipped_shared: 0, ips: {},
  domains: { 'b.example': { malware: 'x', threat: 'botnet_cc', feed: 'threatfox' }, 'a.example': { malware: 'x', threat: 'botnet_cc', feed: 'threatfox' } },
};

function worker(blockDomains: boolean, enforcing: boolean, hooked: boolean) {
  const dir = mkdtempSync(join(tmpdir(), 'tc-resolver-'));
  const hooks = { dnsmasq: join(dir, 'dnsmasq-hook.conf'), unbound: join(dir, 'unbound-hook.conf') };
  if (hooked) { writeFileSync(hooks.dnsmasq, ''); writeFileSync(hooks.unbound, ''); }
  const calls: string[] = [];
  const feeds = new ThreatFeeds({
    settings: { ...threatFeedSettings({ block_domains: blockDomains }), allow: [] },
    enforcing,
    cachePath: join(dir, 'threat-feeds.json'),
    resolverHooks: hooks,
    bus: { publish: () => {}, announceModule: () => {} },
    log: () => {},
    run: (cmd, args) => { calls.push(`${cmd} ${args.join(' ')}`); return ''; },
  });
  return { feeds, dir, calls };
}

describe('daemon resolver files', () => {
  it('lists the domains, sorted, and reloads hooked resolvers only when content changed', () => {
    const w = worker(true, true, true);
    expect(w.feeds.writeResolverFiles(SET)).toBe('; 2 domains refused via dnsmasq + unbound');
    expect(readFileSync(join(w.dir, 'blocked-domains.hosts'), 'utf-8')).toContain('0.0.0.0 a.example\n:: a.example\n0.0.0.0 b.example');
    expect(w.calls).toEqual(['systemctl kill -s HUP dnsmasq.service', 'unbound-control reload']);
    w.feeds.writeResolverFiles(SET);
    expect(w.calls).toHaveLength(2); // nothing new, no reload
  });

  it('writes empty lists when not opted in or not enforcing, and says why', () => {
    const off = worker(false, true, true);
    expect(off.feeds.writeResolverFiles(SET)).toBe('');
    expect(readFileSync(join(off.dir, 'blocked-domains.unbound.conf'), 'utf-8')).not.toContain('local-zone');
    expect(worker(true, false, true).feeds.writeResolverFiles(SET)).toMatch(/remediation is dry_run/);
    expect(worker(true, true, false).feeds.writeResolverFiles(SET)).toMatch(/no resolver hook/);
  });
});

function fakeIO(over: { checkFails?: boolean; apparmor?: boolean } = {}) {
  const files = new Map<string, string>();
  if (over.apparmor) {
    files.set('/etc/apparmor.d/local/usr.sbin.unbound', '# local\n');
    files.set('/etc/apparmor.d/usr.sbin.unbound', 'profile');
  }
  const runs: string[] = [];
  const io: ResolverIO = {
    exists: (p) => files.has(p),
    read: (p) => files.get(p) ?? null,
    write: (p, c) => { files.set(p, c); },
    remove: (p) => { files.delete(p); },
    run: (cmd, args) => {
      runs.push(`${cmd} ${args.join(' ')}`);
      if ((cmd === 'dnsmasq' && args[0] === '--test') || cmd === 'unbound-checkconf') {
        return over.checkFails ? { code: 1, out: 'syntax error at line 3' } : { code: 0, out: 'ok' };
      }
      return { code: 0, out: '' };
    },
  };
  return { io, files, runs };
}

describe('feeds resolver install/remove', () => {
  const state = '/var/lib/threatcrush';

  it('installs the dnsmasq hook, validates, then restarts', () => {
    const f = fakeIO();
    const r = installHook('dnsmasq', state, f.io);
    expect(r.ok).toBe(true);
    expect(f.files.get(RESOLVER_HOOKS.dnsmasq)).toBe(hookContent('dnsmasq', state));
    expect(f.files.get(`${state}/blocked-domains.hosts`)).toMatch(/^# Written by threatcrushd/);
    expect(f.runs.indexOf('dnsmasq --test')).toBeLessThan(f.runs.indexOf('systemctl restart dnsmasq.service'));
  });

  it('rolls the hook back when the resolver rejects the config, and never restarts', () => {
    const f = fakeIO({ checkFails: true });
    const r = installHook('unbound', state, f.io);
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/rejected the config, so nothing was changed: syntax error/);
    expect(f.files.has(RESOLVER_HOOKS.unbound)).toBe(false);
    expect(f.runs.some((c) => c.startsWith('systemctl restart'))).toBe(false);
  });

  it('adds the AppArmor read rule for unbound once, and removes it with the hook', () => {
    const f = fakeIO({ apparmor: true });
    installHook('unbound', state, f.io);
    installHook('unbound', state, f.io);
    const local = f.files.get('/etc/apparmor.d/local/usr.sbin.unbound')!;
    expect(local.split(apparmorRule(state)).length - 1).toBe(1);
    expect(f.runs).toContain('apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound');
    expect(removeHook('unbound', state, f.io)).toMatch(/removed; unbound restarted/);
    expect(f.files.get('/etc/apparmor.d/local/usr.sbin.unbound')).not.toContain('threatcrush');
  });
});
