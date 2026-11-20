import { describe, expect, it } from 'vitest';
import { connectionsFrom, parseSs, peerIp, refuseIp, sshdSessionPids } from '../respond/ip.js';
import { planRespond } from '../respond/plan.js';
import type { Snapshot } from '../respond/types.js';

describe('refuseIp: protected and private ranges', () => {
  it.each([
    ['10.1.2.3', /private\/loopback/],
    ['192.168.1.1', /private/],
    ['127.0.0.1', /loopback/],
    ['100.100.1.1', /100\.64\.0\.0\/10/],
    ['fd7a:115c:a1e0::1', /fc00::\/7/],
    ['::1', /::1\/128/],
    ['104.16.1.1', /shared infrastructure/],
    ['1.1.1.1', /shared infrastructure/],
    ['not-an-ip', /not an IP/],
  ])('refuses %s', (ip, why) => {
    expect(refuseIp(ip, {})).toMatch(why);
  });

  it('refuses the gateway, the allowlist and the session running the command', () => {
    expect(refuseIp('198.51.100.1', { gateways: ['198.51.100.1'] })).toMatch(/gateway/);
    expect(refuseIp('198.51.100.9', { allowlist: ['198.51.100.0/24'] })).toMatch(/protected list/);
    expect(refuseIp('198.51.100.7', { ownClient: '198.51.100.7' })).toMatch(/session running this command/);
  });

  it('allows a public attacker address', () => {
    expect(refuseIp('203.0.113.7', { gateways: ['198.51.100.1'], ownClient: '198.51.100.7' })).toBeNull();
    expect(refuseIp('2001:db8::7', {})).toBeNull();
  });
});

const SS = [
  'LISTEN 0      128    0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=900,fd=3))',
  'ESTAB  0      0      10.0.0.5:22        203.0.113.7:50111 users:(("sshd-session",pid=1201,fd=4),("sshd-session",pid=1230,fd=4))',
  'ESTAB  0      0      10.0.0.5:443       203.0.113.7:50200 users:(("nginx",pid=700,fd=12))',
  'ESTAB  0      0      [2001:db8::5]:22   [2001:db8::7]:40000 users:(("sshd",pid=1500,fd=4))',
  'ESTAB  0      0      [::ffff:10.0.0.5]:8080 [::ffff:203.0.113.7]:50300 users:(("node",pid=800,fd=20))',
  'ESTAB  0      0      10.0.0.5:22        198.51.100.7:40404 users:(("sshd-session",pid=1100,fd=4))',
].join('\n');

describe('ss parsing', () => {
  const conns = parseSs(SS);

  it('keeps only established connections and their processes', () => {
    expect(conns).toHaveLength(5);
    expect(conns[0].processes).toEqual([{ name: 'sshd-session', pid: 1201 }, { name: 'sshd-session', pid: 1230 }]);
  });

  it('reads v4, bracketed v6 and v4-mapped peers', () => {
    expect(peerIp('203.0.113.7:50111')).toBe('203.0.113.7');
    expect(peerIp('[2001:db8::7]:40000')).toBe('2001:db8::7');
    expect(peerIp('[::ffff:203.0.113.7]:50300')).toBe('203.0.113.7');
    expect(connectionsFrom(conns, '203.0.113.7')).toHaveLength(3);
  });

  it('kills only per-connection sshd processes of that peer', () => {
    expect(sshdSessionPids(connectionsFrom(conns, '203.0.113.7'))).toEqual([1201, 1230]);
    expect(sshdSessionPids(connectionsFrom(conns, '2001:db8::7'))).toEqual([1500]);
    expect(sshdSessionPids(connectionsFrom(conns, '203.0.113.7'), [1230])).toEqual([1201]);
  });
});

function snapshot(over: Partial<Snapshot> = {}): Snapshot {
  return {
    hostname: 'box1', uid: 0, user: 'anthony', sshConnection: '198.51.100.7 40404 10.0.0.5 22',
    passwd: [], keyFiles: [], privateKeys: [], ss: SS,
    journal: [
      '1795200000.0 box1 sshd-session[1201]: Accepted publickey for root from 203.0.113.7 port 50111 ssh2: ED25519 SHA256:stolenkeyfp',
      '1795100000.0 box1 sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 1 ssh2',
      '1795100001.0 box1 sshd[1]: Invalid user oracle from 203.0.113.7 port 2',
    ].join('\n'),
    gateways: ['10.0.0.1'],
    sshd: { binary: '/usr/sbin/sshd', dumpT: '', mainConfig: '', dropinDir: '/etc/ssh/sshd_config.d', dropins: {}, existing: {}, effectiveRemote: '', effectiveLocal: '' },
    errors: [],
    ...over,
  };
}

describe('planRespond ip', () => {
  it('bans first, then kills sessions and closes sockets, and lists the logins', () => {
    const r = planRespond(snapshot(), { sub: 'ip', apply: false, ips: ['203.0.113.7'] }, { host: 'box1', via: 'local' });
    expect(r.actions.map((a) => a.kind)).toEqual(['ban', 'kill', 'ss-kill']);
    expect(r.actions.every((a) => a.status === 'planned')).toBe(true);
    expect(r.actions[0].op).toEqual({ op: 'ban', ip: '203.0.113.7', ttl: '30d' });
    expect(r.actions[1].op).toEqual({ op: 'kill', pids: [1201, 1230] });
    expect(r.logins).toEqual([{ at: 1795200000000, user: 'root', method: 'publickey', fingerprint: 'SHA256:stolenkeyfp', ip: '203.0.113.7' }]);
    expect(r.failedAttempts).toEqual({ '203.0.113.7': 2 });
  });

  it('refuses private ranges and the operator’s own session, touching nothing for them', () => {
    const r = planRespond(snapshot(), { sub: 'ip', apply: true, ips: ['10.9.9.9', '198.51.100.7'] }, { host: 'box1', via: 'local' });
    expect(r.actions.map((a) => [a.kind, a.status])).toEqual([['ban', 'refused'], ['ban', 'refused']]);
  });

  it('without root, plans read-only and says what needs root', () => {
    const r = planRespond(snapshot({ uid: 1000 }), { sub: 'ip', apply: true, ips: ['203.0.113.7'] }, { host: 'box1', via: 'local' });
    expect(r.actions.every((a) => a.status === 'needs-root')).toBe(true);
    expect(r.needsRoot).toHaveLength(3);
  });
});
