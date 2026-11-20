import { describe, expect, it } from 'vitest';
import {
  assessExposure, classifyExposures, evaluateIptChain, evaluateNftChain, evaluateUfw, findDockerUserRestore,
  findIneffectiveDockerUserRules, isEmptyDockerUser, isLoopback, isPrivate, parseDockerPsPorts, parseIptablesChain,
  parseNftInputChains, parseProcNetTcp, parseSsListeners, parseUfwStatus, unitExecPaths, type FirewallVerdict,
} from '../host-scan/exposure.js';

const SS = `LISTEN 0      128          10.200.68.1:18443      0.0.0.0:* users:(("ssh",pid=947522,fd=5))
LISTEN 0      512              0.0.0.0:18093      0.0.0.0:* users:(("bun",pid=470683,fd=8))
LISTEN 0      4096           127.0.0.1:5434       0.0.0.0:*
LISTEN 0      244              0.0.0.0:5432       0.0.0.0:* users:(("postgres",pid=900,fd=6))
LISTEN 0      244                    *:6379             *:* users:(("redis-server",pid=901,fd=7))
LISTEN 0      4096                [::]:5601          [::]:* users:(("docker-proxy",pid=902,fd=4))
LISTEN 0      4096             0.0.0.0:5601       0.0.0.0:* users:(("docker-proxy",pid=903,fd=4))
LISTEN 0      4096       127.0.0.53%lo:53         0.0.0.0:*
LISTEN 0      128                [::1]:631           [::]:*
`;

const DOCKER_PS = `supabase-pgbouncer\t5432/tcp, 0.0.0.0:6543->6432/tcp, [::]:6543->6432/tcp
supabase-db\t0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp
pit-world-supabase-db\t0.0.0.0:5601->5432/tcp, [::]:5601->5432/tcp
agentdb-db\t127.0.0.1:55433->5432/tcp
web\t0.0.0.0:8000-8001->3000-3001/tcp
old-docker\t:::7000->6379/tcp
`;

// The dev2 DOCKER-USER chain as it stood after the 2026-11-20 lockdown (addresses are documentation ranges).
const DOCKER_USER = `-N DOCKER-USER
-A DOCKER-USER -i enp11s0 -p tcp -m tcp --dport 5432 -j DROP
-A DOCKER-USER -i enp11s0 -p tcp -m tcp --dport 6432 -j DROP
-A DOCKER-USER -s 203.0.113.9/32 -p tcp -m tcp --dport 5601 -j ACCEPT
-A DOCKER-USER -s 10.0.0.0/8 -p tcp -m tcp --dport 5601 -j ACCEPT
-A DOCKER-USER -p tcp -m tcp --dport 5601 -j DROP
-A DOCKER-USER -s 127.0.0.1/32 -p tcp -m conntrack --ctorigdstport 8000 -j ACCEPT
-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8000 -j DROP
-A DOCKER-USER -i enp11s0 -p tcp -m conntrack --ctorigdstport 6543 --ctdir ORIGINAL -j DROP
-A DOCKER-USER -j RETURN
`;

describe('listeners', () => {
  it('parses ss output with and without process info', () => {
    const l = parseSsListeners(SS);
    expect(l).toHaveLength(9);
    expect(l[0]).toMatchObject({ addr: '10.200.68.1', port: 18443, family: 4, process: 'ssh', pid: 947522 });
    expect(l[2]).toMatchObject({ addr: '127.0.0.1', port: 5434, process: undefined });
    expect(l[4]).toMatchObject({ addr: '*', port: 6379, family: 46 });
    expect(l[5]).toMatchObject({ addr: '::', port: 5601, family: 6, process: 'docker-proxy' });
    expect(l[7]).toMatchObject({ addr: '127.0.0.53', port: 53 });
    expect(l[8]).toMatchObject({ addr: '::1', port: 631, family: 6 });
  });

  it('parses /proc/net/tcp and tcp6 LISTEN rows', () => {
    const v4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 34567 1 0000000000000000 100 0 0 10 0
   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 34568 1 0000000000000000 100 0 0 10 0
   2: 0100007F:A2C4 0100007F:1538 01 00000000:00000000 00:00000000 00000000  1000        0 34569 1 0000000000000000 100 0 0 10 0
`;
    const r = parseProcNetTcp(v4, 4);
    expect(r).toHaveLength(2);
    expect(r[0]).toMatchObject({ addr: '0.0.0.0', port: 5432, inode: '34567' });
    expect(r[1]).toMatchObject({ addr: '127.0.0.1', port: 6379 });
    const v6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:18EB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1111 1
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1
`;
    const r6 = parseProcNetTcp(v6, 6);
    expect(r6[0]).toMatchObject({ addr: '::', port: 6379 });
    expect(r6[1]).toMatchObject({ addr: '::1', port: 631 });
  });

  it('knows loopback and private addresses', () => {
    expect(isLoopback('127.0.0.53')).toBe(true);
    expect(isLoopback('::1')).toBe(true);
    expect(isLoopback('0.0.0.0')).toBe(false);
    expect(isPrivate('10.200.68.1')).toBe(true);
    expect(isPrivate('172.20.0.1')).toBe(true);
    expect(isPrivate('fd00::1')).toBe(true);
    expect(isPrivate('203.0.113.9')).toBe(false);
  });
});

describe('docker ps port bindings', () => {
  it('parses published ports, IPv6, ranges, and skips exposed-only ports', () => {
    const m = parseDockerPsPorts(DOCKER_PS);
    expect(m.filter((x) => x.container === 'supabase-pgbouncer')).toEqual([
      { container: 'supabase-pgbouncer', hostIp: '0.0.0.0', hostPort: 6543, containerPort: 6432, proto: 'tcp', family: 4 },
      { container: 'supabase-pgbouncer', hostIp: '::', hostPort: 6543, containerPort: 6432, proto: 'tcp', family: 6 },
    ]);
    expect(m.filter((x) => x.container === 'web').map((x) => [x.hostPort, x.containerPort])).toEqual([[8000, 3000], [8001, 3001]]);
    expect(m.find((x) => x.container === 'old-docker')).toMatchObject({ hostIp: '::', hostPort: 7000, containerPort: 6379, family: 6 });
  });
});

describe('classifyExposures', () => {
  const listeners = parseSsListeners(SS);
  const mappings = parseDockerPsPorts(DOCKER_PS);

  it('classifies Docker mappings by CONTAINER port (5601->5432 and 6543->6432 are postgres)', () => {
    const { sensitive } = classifyExposures(listeners, mappings, { hasGlobalV6: false, dockerKnown: true });
    const docker = sensitive.filter((e) => e.kind === 'docker');
    expect(docker.map((e) => [e.hostPort, e.containerPort, e.service])).toEqual([
      [6543, 6432, 'pgbouncer'], [5432, 5432, 'postgres'], [5601, 5432, 'postgres'],
    ]);
    // 127.0.0.1:55433 is not public; IPv6 bindings are ignored without a global v6 address.
    expect(docker.every((e) => e.family === 4)).toBe(true);
  });

  it('reports host processes on wildcard addresses, skipping loopback, private and docker-proxy', () => {
    const { sensitive } = classifyExposures(listeners, mappings, { hasGlobalV6: false, dockerKnown: true });
    const host = sensitive.filter((e) => e.kind === 'host');
    // 0.0.0.0:5432 belongs to supabase-db's mapping, so it is judged as Docker, not twice.
    expect(host.map((e) => [e.hostPort, e.service, e.process])).toEqual([[6379, 'redis', 'redis-server']]);
  });

  it('includes IPv6 when the host has a global v6 address', () => {
    const { sensitive } = classifyExposures(listeners, mappings, { hasGlobalV6: true, dockerKnown: true });
    expect(sensitive.some((e) => e.kind === 'docker' && e.family === 6 && e.hostPort === 6543)).toBe(true);
    expect(sensitive.some((e) => e.kind === 'host' && e.family === 6 && e.hostPort === 6379)).toBe(true);
  });

  it('falls back to docker-proxy listeners when docker ps is unavailable', () => {
    const { sensitive } = classifyExposures(listeners, [], { hasGlobalV6: false, dockerKnown: false });
    expect(sensitive.find((e) => e.hostPort === 5432)).toMatchObject({ kind: 'host', process: 'postgres' });
    // 5601 is not itself a datastore port, so without the mapping it is invisible: the reason docker ps matters.
    expect(sensitive.find((e) => e.hostPort === 5601)).toBeUndefined();
  });
});

describe('DOCKER-USER matching', () => {
  const chain = parseIptablesChain(DOCKER_USER, 'DOCKER-USER');

  it('parses rules', () => {
    expect(chain.rules).toHaveLength(9);
    expect(chain.rules[0]).toMatchObject({ iface: 'enp11s0', proto: 'tcp', dports: [[5432, 5432]], target: 'DROP' });
    expect(chain.rules[5]).toMatchObject({ ctorigdstports: [[8000, 8000]], source: '127.0.0.1/32', target: 'ACCEPT' });
    expect(isEmptyDockerUser(chain)).toBe(false);
    expect(isEmptyDockerUser(parseIptablesChain('-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n', 'DOCKER-USER'))).toBe(true);
  });

  it('matches post-DNAT --dport against the CONTAINER port', () => {
    // 0.0.0.0:5601->5432: the --dport 5432 DROP catches it, the --dport 5601 rules never see it.
    expect(evaluateIptChain(chain, { dport: 5432, origDport: 5601 }, 'open')).toMatchObject({ verdict: 'blocked', by: expect.stringContaining('--dport 5432') });
    // 6543->6432: blocked by --dport 6432 before the ctorigdstport rule.
    expect(evaluateIptChain(chain, { dport: 6432, origDport: 6543 }, 'open').verdict).toBe('blocked');
  });

  it('matches --ctorigdstport against the HOST port', () => {
    const only = parseIptablesChain('-A DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 6543 --ctdir ORIGINAL -j DROP\n-A DOCKER-USER -j RETURN', 'DOCKER-USER');
    expect(evaluateIptChain(only, { dport: 6432, origDport: 6543 }, 'open').verdict).toBe('blocked');
    expect(evaluateIptChain(only, { dport: 6543, origDport: 6432 }, 'open').verdict).toBe('open');
    // A --dport rule on the host port does nothing for 6543->6432.
    const wrong = parseIptablesChain('-A DOCKER-USER -p tcp --dport 6543 -j DROP\n-A DOCKER-USER -j RETURN', 'DOCKER-USER');
    expect(evaluateIptChain(wrong, { dport: 6432, origDport: 6543 }, 'open').verdict).toBe('open');
  });

  it('treats source-limited ACCEPTs as an allowlist and source-limited DROPs as no block', () => {
    const v = evaluateIptChain(chain, { dport: 3000, origDport: 8000 }, 'open');
    expect(v).toMatchObject({ verdict: 'blocked', allowlisted: ['127.0.0.1/32'] });
    const partial = parseIptablesChain('-A DOCKER-USER -s 198.51.100.0/24 -p tcp --dport 5432 -j DROP', 'DOCKER-USER');
    expect(evaluateIptChain(partial, { dport: 5432, origDport: 5432 }, 'open').verdict).toBe('open');
    const negated = parseIptablesChain('-A DOCKER-USER ! -s 10.0.0.0/8 -p tcp --dport 5432 -j DROP', 'DOCKER-USER');
    expect(evaluateIptChain(negated, { dport: 5432, origDport: 5432 }, 'open').verdict).toBe('blocked');
  });

  it('ignores ESTABLISHED-only rules and other protocols; honours multiport ranges', () => {
    const c = parseIptablesChain(`-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-USER -p udp --dport 5432 -j ACCEPT
-A DOCKER-USER -p tcp -m multiport --dports 3306,5000:6000 -j DROP`, 'DOCKER-USER');
    expect(evaluateIptChain(c, { dport: 5432, origDport: 5432 }, 'open').verdict).toBe('blocked');
    expect(evaluateIptChain(c, { dport: 6379, origDport: 6379 }, 'open').verdict).toBe('open');
  });

  it('flags --dport rules written for a host port that DNAT rewrites', () => {
    const bad = findIneffectiveDockerUserRules(chain, parseDockerPsPorts(DOCKER_PS).filter((m) => m.family === 4));
    expect(bad.map((b) => [b.hostPort, b.containerPort, b.container])).toEqual([
      [5601, 5432, 'pit-world-supabase-db'], [5601, 5432, 'pit-world-supabase-db'], [5601, 5432, 'pit-world-supabase-db'],
    ]);
  });

  it('INPUT chains fall back to the policy', () => {
    const input = parseIptablesChain('-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT', 'INPUT');
    expect(evaluateIptChain(input, { dport: 5432, origDport: 5432 })).toMatchObject({ verdict: 'blocked', by: 'policy DROP' });
    expect(evaluateIptChain(input, { dport: 22, origDport: 22 }).verdict).toBe('open');
  });
});

describe('ufw and nftables', () => {
  const UFW = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
5432                       ALLOW IN    10.0.0.0/8                 # office
6379/tcp                   ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
9000:9100/tcp              DENY IN     Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`;
  const ufw = parseUfwStatus(UFW);

  it('parses ufw status verbose', () => {
    expect(ufw).toMatchObject({ active: true, defaultIncoming: 'deny' });
    expect(ufw.rules).toHaveLength(6);
    expect(ufw.rules[1]).toEqual({ to: '5432', action: 'ALLOW IN', from: '10.0.0.0/8', v6: false });
  });

  it('evaluates ufw first-match with the default', () => {
    expect(evaluateUfw(ufw, 5432, 4)).toMatchObject({ verdict: 'blocked', allowlisted: ['10.0.0.0/8'] });
    expect(evaluateUfw(ufw, 6379, 4).verdict).toBe('open');
    expect(evaluateUfw(ufw, 9042, 4).verdict).toBe('blocked');
    expect(evaluateUfw(parseUfwStatus('Status: inactive\n'), 5432, 4).verdict).toBe('unknown');
  });

  it('parses native nft input chains and skips iptables-nft tables', () => {
    const NFT = `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
	}
}
table inet fw {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iifname "lo" accept
		tcp dport { 22, 80, 443 } accept
		ip saddr 10.0.0.0/8 tcp dport 5432 accept
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
table inet tor {
	chain input {
		type filter hook input priority -100; policy accept;
		tcp dport 22 ip saddr @exits drop
	}
}`;
    const chains = parseNftInputChains(NFT);
    expect(chains.map((c) => `${c.family} ${c.table}`)).toEqual(['inet fw', 'inet tor']);
    expect(evaluateNftChain(chains[0], 5432, 4).verdict).toBe('blocked');
    expect(evaluateNftChain(chains[0], 443, 4).verdict).toBe('open');
    expect(evaluateNftChain(chains[1], 5432, 4).verdict).toBe('open');
  });
});

describe('boot persistence', () => {
  it('finds units, scripts and rules.v4 that restore DOCKER-USER', () => {
    const found = findDockerUserRestore([
      { path: '/etc/iptables/rules.v4', content: '*filter\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -j RETURN\nCOMMIT\n' },
      { path: '/usr/local/sbin/docker-user-fw', content: '#!/bin/sh\niptables -I DOCKER-USER -p tcp --dport 5432 -j DROP\n' },
      { path: '/etc/systemd/system/unrelated.service', content: '[Service]\nExecStart=/usr/bin/true\n' },
    ]);
    expect(found).toEqual(['/usr/local/sbin/docker-user-fw']);
    expect(findDockerUserRestore([{ path: '/etc/iptables/rules.v4', content: '-A DOCKER-USER -p tcp --dport 5432 -j DROP\n' }])).toEqual(['/etc/iptables/rules.v4']);
  });

  it('reads ExecStart paths from units', () => {
    expect(unitExecPaths('[Service]\nExecStartPre=-/usr/local/sbin/a\nExecStart=/usr/local/sbin/docker-user-fw --apply\n')).toEqual(['/usr/local/sbin/a', '/usr/local/sbin/docker-user-fw']);
  });
});

describe('assessExposure', () => {
  const mappings = parseDockerPsPorts(DOCKER_PS).filter((m) => m.family === 4);
  const { sensitive, publicCount } = classifyExposures(parseSsListeners(SS), mappings, { hasGlobalV6: false, dockerKnown: true });
  const blocked: FirewallVerdict = { verdict: 'blocked', by: 'ufw default deny (incoming)' };

  it('the 2026-11-20 incident: empty DOCKER-USER fails every published datastore', () => {
    const empty = parseIptablesChain('-A DOCKER-USER -j RETURN', 'DOCKER-USER');
    const items = assessExposure({ root: true, exposures: sensitive, publicCount, mappings, dockerUser: { 4: empty, 6: null }, hostVerdict: () => blocked, restoreFiles: null });
    const fails = items.filter((i) => i.status === 'fail');
    expect(fails.map((f) => f.details?.host_port)).toEqual([6543, 5432, 5601]);
    expect(fails[0].message).toContain('ufw and INPUT do not apply');
    expect(items.some((i) => i.status === 'warn' && /DOCKER-USER chain is empty/.test(i.message))).toBe(true);
  });

  it('a locked-down chain passes the ports but warns when nothing restores it at boot', () => {
    const chain = parseIptablesChain(DOCKER_USER, 'DOCKER-USER');
    const items = assessExposure({ root: true, exposures: sensitive, publicCount, mappings, dockerUser: { 4: chain, 6: null }, hostVerdict: () => blocked, restoreFiles: [] });
    expect(items.filter((i) => i.status === 'fail')).toEqual([]);
    expect(items.some((i) => /nothing restores them at boot/.test(i.message))).toBe(true);
    expect(items.filter((i) => /3 DOCKER-USER rule\(s\) on --dport 5601 never match pit-world-supabase-db/.test(i.message))).toHaveLength(1);
    const persisted = assessExposure({ root: true, exposures: sensitive, publicCount, mappings, dockerUser: { 4: chain, 6: null }, hostVerdict: () => blocked, restoreFiles: ['/usr/local/sbin/docker-user-fw'] });
    expect(persisted.some((i) => /nothing restores/.test(i.message))).toBe(false);
  });

  it('host processes use the host firewall verdict', () => {
    const chain = parseIptablesChain(DOCKER_USER, 'DOCKER-USER');
    const items = assessExposure({ root: true, exposures: sensitive, publicCount, mappings, dockerUser: { 4: chain, 6: null }, hostVerdict: () => ({ verdict: 'open', by: 'policy ACCEPT' }), restoreFiles: ['x'] });
    expect(items.filter((i) => i.status === 'fail').map((i) => i.details?.host_port)).toEqual([6379]);
  });

  it('without root, every sensitive exposure is a warning', () => {
    const items = assessExposure({ root: false, exposures: sensitive, publicCount, mappings, dockerUser: { 4: null, 6: null }, hostVerdict: () => blocked, restoreFiles: null });
    expect(items.every((i) => i.status === 'warn' && /without root/.test(i.message))).toBe(true);
    expect(items).toHaveLength(sensitive.length);
  });
});
