import { describe, it, expect, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import type { ThreatEvent } from '../../types/events.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {}, getModuleState: () => undefined, setModuleState: () => {} }));

const {
  classifyLogin,
  groupMembers,
  networkOf,
  loginWatchSettings,
  parseAcceptedLogins,
  ssPeerIp,
  sshdPidsForPeer,
  killSshSessions,
  LoginWatch,
} = await import('../workers/login-watch.js');

const TOR = '185.220.101.7';
const PROXY = '45.86.200.12';

const GROUP = [
  'root:x:0:',
  'sudo:x:27:anthony,ops',
  'docker:x:999:deployer',
  'wheel:x:10:',
  'users:x:100:alice',
  'admins:x:1500:',
].join('\n');
const PASSWD = [
  'root:x:0:0:root:/root:/bin/bash',
  'anthony:x:1000:1000::/home/anthony:/bin/zsh',
  'wheelie:x:1001:10::/home/wheelie:/bin/bash',
  'alice:x:1002:100::/home/alice:/bin/bash',
].join('\n');

function ctx(over: Partial<Parameters<typeof classifyLogin>[1]> = {}) {
  const sensitive = new Set(['root', ...groupMembers(GROUP, PASSWD, ['sudo', 'admin', 'wheel', 'docker'])]);
  return {
    isTor: (ip: string) => ip === TOR,
    sensitive: (u: string) => sensitive.has(u),
    trusted: () => false,
    ...over,
  };
}

describe('groupMembers', () => {
  it('reads listed members and primary-group members', () => {
    expect([...groupMembers(GROUP, PASSWD, ['sudo', 'admin', 'wheel', 'docker'])].sort()).toEqual(['anthony', 'deployer', 'ops', 'wheelie']);
  });
});

describe('networkOf', () => {
  it('is the /24 for IPv4 and v4-mapped, the /48 for IPv6', () => {
    expect(networkOf('203.0.113.77')).toBe('203.0.113.0/24');
    expect(networkOf('::ffff:203.0.113.77')).toBe('203.0.113.0/24');
    expect(networkOf('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::/48');
    expect(networkOf('nope')).toBeNull();
  });
});

describe('classifyLogin', () => {
  it('a Tor exit is critical for anyone', () => {
    const v = classifyLogin({ user: 'alice', ip: TOR }, ctx());
    expect(v).toMatchObject({ ruleId: 'ssh-login-tor', severity: 'critical' });
    expect(v!.reasons).toContain('tor_exit');
  });

  it('root from an untrusted public address is critical; a sudoer is high', () => {
    expect(classifyLogin({ user: 'root', ip: PROXY }, ctx())).toMatchObject({ ruleId: 'ssh-login-sensitive', severity: 'critical' });
    expect(classifyLogin({ user: 'anthony', ip: PROXY }, ctx())).toMatchObject({ ruleId: 'ssh-login-sensitive', severity: 'high' });
    expect(classifyLogin({ user: 'deployer', ip: PROXY }, ctx())).toMatchObject({ severity: 'high' });
  });

  it('an ordinary user from a public address is not flagged (first-seen off)', () => {
    expect(classifyLogin({ user: 'alice', ip: PROXY }, ctx())).toBeNull();
  });

  it('the allowlist (trusted_login_cidrs) silences sensitive users', () => {
    const settings = loginWatchSettings({ trusted_login_cidrs: ['45.86.200.0/24'] });
    expect(settings.trustedCidrs).toEqual(['45.86.200.0/24']);
    const trusted = (ip: string) => ip.startsWith('45.86.200.');
    expect(classifyLogin({ user: 'root', ip: PROXY }, ctx({ trusted }))).toBeNull();
    // …but never a Tor exit.
    expect(classifyLogin({ user: 'root', ip: TOR }, ctx({ trusted: () => true }))).toMatchObject({ ruleId: 'ssh-login-tor' });
  });

  it('private, loopback and tailnet ranges are never flagged', () => {
    for (const ip of ['10.1.2.3', '172.20.0.5', '192.168.1.9', '100.100.1.1', '127.0.0.1', '::1', 'fd00::5', 'fd7a:115c:a1e0::1']) {
      expect(classifyLogin({ user: 'root', ip }, ctx({ seenNetwork: () => false })), ip).toBeNull();
    }
  });

  it('first login from a /24 is medium; a known /24 is quiet', () => {
    const seen = new Set(['alice|203.0.113.0/24']);
    const seenNetwork = (u: string, n: string) => seen.has(`${u}|${n}`);
    expect(classifyLogin({ user: 'alice', ip: '203.0.113.200' }, ctx({ seenNetwork }))).toBeNull();
    expect(classifyLogin({ user: 'alice', ip: '198.51.100.4' }, ctx({ seenNetwork }))).toMatchObject({ ruleId: 'ssh-login-new-network', severity: 'medium', network: '198.51.100.0/24' });
    // Combined with a sensitive user, the higher rule wins and both reasons stay.
    const v = classifyLogin({ user: 'root', ip: '198.51.100.4' }, ctx({ seenNetwork }));
    expect(v).toMatchObject({ ruleId: 'ssh-login-sensitive', severity: 'critical' });
    expect(v!.reasons).toEqual(['sensitive_user', 'first_seen_network']);
  });
});

describe('settings', () => {
  it('defaults: on, root + sudo/admin/wheel/docker, no trusted CIDRs, auto_response off', () => {
    const s = loginWatchSettings();
    expect(s).toMatchObject({ enabled: true, sensitiveUsers: ['root'], sensitiveGroups: ['sudo', 'admin', 'wheel', 'docker'], trustedCidrs: [], firstSeen: true, autoResponse: false });
    expect(loginWatchSettings({ sensitive_users: ['deploy'] }).sensitiveUsers).toEqual(['root', 'deploy']);
  });
});

describe('journal baseline + ss parsing', () => {
  it('parses accepted logins from short-unix journal output', () => {
    const text = '1763600000.123 dev2 sshd-session[1]: Accepted publickey for anthony from 203.0.113.9 port 50000 ssh2: ED25519 SHA256:abc\n1763600001.0 dev2 sshd[2]: Failed password for root from 1.2.3.4 port 1 ssh2';
    expect(parseAcceptedLogins(text)).toEqual([{ user: 'anthony', ip: '203.0.113.9', at: 1763600000123 }]);
  });

  it('reads peers and sshd pids from ss', () => {
    expect(ssPeerIp('[::ffff:45.86.200.12]:5555')).toBe('45.86.200.12');
    expect(ssPeerIp('[2001:db8::1]:22')).toBe('2001:db8::1');
    expect(ssPeerIp('45.86.200.12:5555')).toBe('45.86.200.12');
    const ss = [
      `0 0 10.0.0.5:22 ${PROXY}:5555 users:(("sshd-session",pid=4100,fd=4),("sshd-session",pid=4120,fd=4))`,
      '0 0 10.0.0.5:22 203.0.113.9:6000 users:(("sshd-session",pid=5000,fd=4))',
      `0 0 10.0.0.5:443 ${PROXY}:7000 users:(("nginx",pid=77,fd=9))`,
    ].join('\n');
    expect(sshdPidsForPeer(ss, PROXY)).toEqual([4100, 4120]);
  });

  it('kills only that user\'s session processes', () => {
    const killed: number[] = [];
    const cmd: Record<number, string> = { 4100: 'sshd-session: root [priv]', 4120: 'sshd-session: root@pts/3', 4130: 'sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups' };
    const out = killSshSessions('root', PROXY, {
      run: () => `0 0 10.0.0.5:22 ${PROXY}:5555 users:(("sshd-session",pid=4100,fd=4),("sshd-session",pid=4120,fd=4),("sshd",pid=4130,fd=3))`,
      cmdline: (pid) => cmd[pid] ?? null,
      kill: (pid) => { killed.push(pid); },
    });
    expect(out).toEqual([4100, 4120]);
    expect(killed).toEqual([4100, 4120]);
    expect(killSshSessions('anthony', PROXY, { run: () => `0 0 a:22 ${PROXY}:1 users:(("sshd-session",pid=4100,fd=4))`, cmdline: () => 'sshd-session: root [priv]', kill: () => { throw new Error('no'); } })).toEqual([]);
  });
});

function accepted(user: string, ip: string, fp = 'SHA256:stolenKeyFingerprint'): ThreatEvent {
  return {
    timestamp: new Date('2026-11-20T03:00:00Z'),
    module: 'ssh-guard',
    category: 'auth',
    severity: 'info',
    message: `SSH login accepted for ${user}`,
    source_ip: ip,
    details: { user, ssh_user: user, auth_method: 'publickey', fingerprint: fp },
  };
}

function watch(opts: { autoResponse?: boolean; dryRun?: boolean; fleet?: string[]; seen?: Record<string, Record<string, { first: string; last: string; count: number }>> } = {}) {
  const bus = new EventEmitter() as EventEmitter & { publish(e: ThreatEvent): void };
  const published: ThreatEvent[] = [];
  bus.publish = (e) => published.push(e);
  let saved: unknown = null;
  const killed: number[] = [];
  const w = new LoginWatch({
    bus,
    settings: loginWatchSettings({ auto_response: opts.autoResponse }),
    tor: { has: (ip) => ip === TOR },
    manager: { isFleetAddress: (ip) => (opts.fleet ?? []).includes(ip), status: () => ({ dry_run: opts.dryRun === true }) },
    log: () => {},
    store: { load: () => opts.seen ?? null, save: (s) => { saved = JSON.parse(JSON.stringify(s)); } },
    readAccounts: () => ({ group: GROUP, passwd: PASSWD }),
    run: () => '',
    killDeps: {
      run: () => `0 0 10.0.0.5:22 ${PROXY}:5555 users:(("sshd-session",pid=4100,fd=4))`,
      cmdline: () => 'sshd-session: root [priv]',
      kill: (pid) => { killed.push(pid); },
    },
  });
  w.start();
  return { bus, published, killed, saved: () => saved, w };
}

describe('LoginWatch', () => {
  it('alerts on root from a proxy with the key fingerprint and IP, without banning by default', () => {
    const { bus, published, killed } = watch();
    bus.emit('event', accepted('root', PROXY));
    expect(published).toHaveLength(1);
    const e = published[0];
    expect(e).toMatchObject({ module: 'login-watch', severity: 'critical', source_ip: PROXY });
    expect(e.message).toContain('SHA256:stolenKeyFingerprint');
    expect(e.message).toContain(PROXY);
    expect(e.details).toMatchObject({ rule_id: 'ssh-login-sensitive', fingerprint: 'SHA256:stolenKeyFingerprint', auto_response: false });
    expect(e.details?.remediation).toBeUndefined();
    expect(killed).toEqual([]);
  });

  it('auto_response bans (via remediation) and kills the session', () => {
    const { bus, published, killed } = watch({ autoResponse: true });
    bus.emit('event', accepted('root', PROXY));
    expect(published[0].details?.remediation).toMatchObject({ action: 'block', ban_on_login: true, override_operator_protection: true });
    expect(killed).toEqual([4100]);
  });

  it('auto_response does nothing in dry_run, or to our own addresses', () => {
    const dry = watch({ autoResponse: true, dryRun: true });
    dry.bus.emit('event', accepted('root', PROXY));
    expect(dry.killed).toEqual([]);
    expect(dry.published[0].message).toContain('dry_run');

    const fleet = watch({ autoResponse: true, fleet: [PROXY] });
    fleet.bus.emit('event', accepted('root', PROXY));
    // A configured protected address is trusted: no alert and no action.
    expect(fleet.published).toEqual([]);
    expect(fleet.killed).toEqual([]);
  });

  it('remembers networks and flags a user\'s first /24 at medium', () => {
    const seen = { alice: { '203.0.113.0/24': { first: 'x', last: 'x', count: 3 } } };
    const { bus, published, saved } = watch({ seen });
    bus.emit('event', accepted('alice', '203.0.113.50'));
    expect(published).toEqual([]);
    bus.emit('event', accepted('alice', '198.51.100.4'));
    expect(published[0]).toMatchObject({ severity: 'medium', details: { rule_id: 'ssh-login-new-network' } });
    bus.emit('event', accepted('alice', '198.51.100.99'));
    expect(published).toHaveLength(1);
    expect(Object.keys((saved() as Record<string, object>).alice).sort()).toEqual(['198.51.100.0/24', '203.0.113.0/24']);
  });

  it('ignores non-login events and private sources', () => {
    const { bus, published } = watch();
    bus.emit('event', { ...accepted('root', PROXY), message: 'Failed SSH login for root' });
    bus.emit('event', accepted('root', '10.0.0.8'));
    bus.emit('event', { ...accepted('root', PROXY), module: 'login-watch' });
    expect(published).toEqual([]);
  });
});
