import { describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildFeedSet,
  matchDomain,
  matchIp,
  parseHostfile,
  parseIpList,
  parseThreatFoxJson,
  readFeedCache,
  type FeedSet,
} from '../threat-feeds/index.js';
import {
  EGRESS_TABLE,
  ThreatFeeds,
  egressRuleset,
  parseListeningPorts,
  parseSs,
  threatFeedSettings,
} from '../../daemon/workers/threat-feeds.js';
import type { ThreatEvent } from '../../types/events.js';

const THREATFOX = JSON.stringify({
  '1': [{ ioc_value: '203.0.113.8:443', ioc_type: 'ip:port', threat_type: 'botnet_cc', malware_printable: 'QakBot', confidence_level: 100 }],
  '2': [{ ioc_value: '198.51.100.9:8080', ioc_type: 'ip:port', threat_type: 'payload_delivery', malware_printable: 'Unknown malware', confidence_level: 75 }],
  '3': [{ ioc_value: '198.51.100.10:80', ioc_type: 'ip:port', threat_type: 'botnet_cc', malware_printable: 'Low', confidence_level: 50 }],
  '4': [{ ioc_value: 'evil-c2.example', ioc_type: 'domain', threat_type: 'botnet_cc', malware_printable: 'Remcos', confidence_level: 100 }],
  '5': [{ ioc_value: 'https://x.example/a', ioc_type: 'url', threat_type: 'payload_delivery', confidence_level: 100 }],
  '6': [{ ioc_value: '104.21.3.4:443', ioc_type: 'ip:port', threat_type: 'botnet_cc', malware_printable: 'Behind CF', confidence_level: 100 }],
  '7': [{ ioc_value: '[2001:db8::5]:443', ioc_type: 'ip:port', threat_type: 'botnet_cc', malware_printable: 'V6', confidence_level: 100 }],
});

describe('feed parsers', () => {
  it('keeps confident C2/payload IPs and domains from ThreatFox, drops URLs and hashes', () => {
    const { ips, domains } = parseThreatFoxJson(THREATFOX, 75);
    expect([...ips.keys()].sort()).toEqual(['104.21.3.4', '198.51.100.9', '2001:db8::5', '203.0.113.8']);
    expect(ips.get('203.0.113.8')).toEqual({ malware: 'QakBot', threat: 'botnet_cc', feed: 'threatfox' });
    expect([...domains.keys()]).toEqual(['evil-c2.example']);
  });

  it('reads host files and IP lists, skipping comments and junk', () => {
    const hosts = parseHostfile('# header\n127.0.0.1\tbad.example\n127.0.0.1 localhost\n127.0.0.1 Bad2.Example.\n\n', 'urlhaus');
    expect([...hosts.keys()]).toEqual(['bad.example', 'bad2.example']);
    expect([...parseIpList('# Feodo\n192.0.2.44\nnot-an-ip\n', 'feodo').keys()]).toEqual(['192.0.2.44']);
  });
});

describe('buildFeedSet', () => {
  it('never lists CDN, resolver, private or allowlisted addresses, nor a shared platform as a whole', () => {
    const set = buildFeedSet([
      { ips: new Map([
        ['203.0.113.8', { malware: 'QakBot', threat: 'botnet_cc', feed: 'threatfox' }],
        ['104.21.3.4', { malware: 'x', threat: 'botnet_cc', feed: 'threatfox' }], // Cloudflare
        ['8.8.8.8', { malware: 'x', threat: 'botnet_cc', feed: 'threatfox' }],
        ['10.1.2.3', { malware: 'x', threat: 'botnet_cc', feed: 'threatfox' }],
        ['198.51.100.9', { malware: 'x', threat: 'payload_delivery', feed: 'threatfox' }], // allowlisted
      ]) },
      { domains: new Map([
        ['workers.dev', { malware: 'unknown', threat: 'malware_host', feed: 'threatfox' }],
        ['evil.workers.dev', { malware: 'unknown', threat: 'malware_host', feed: 'threatfox' }],
        ['partner.example', { malware: 'unknown', threat: 'malware_host', feed: 'urlhaus' }], // allowlisted
      ]) },
    ], ['198.51.100.0/24', 'example'], []);
    expect(Object.keys(set.ips)).toEqual(['203.0.113.8']);
    expect(Object.keys(set.domains)).toEqual(['evil.workers.dev']);
    expect(set.skipped_shared).toBe(6);
  });
});

const SET: FeedSet = {
  fetched_at: '2026-10-17T00:00:00.000Z',
  ips: { '203.0.113.8': { malware: 'QakBot', threat: 'botnet_cc', feed: 'threatfox' } },
  domains: { 'evil-c2.example': { malware: 'Remcos', threat: 'botnet_cc', feed: 'threatfox' } },
  sources: [],
  skipped_shared: 0,
};

describe('matching', () => {
  it('matches a listed domain and its subdomains, never a parent', () => {
    expect(matchDomain('evil-c2.example', SET)?.domain).toBe('evil-c2.example');
    expect(matchDomain('a.b.EVIL-C2.example.', SET)?.domain).toBe('evil-c2.example');
    expect(matchDomain('example', SET)).toBeNull();
    expect(matchDomain('notevil-c2.example', SET)).toBeNull();
  });

  it('matches IPv4-mapped IPv6 forms of a listed IPv4', () => {
    expect(matchIp('::ffff:203.0.113.8', SET)?.malware).toBe('QakBot');
    expect(matchIp('203.0.113.9', SET)).toBeNull();
  });
});

describe('egressRuleset', () => {
  it('replaces the table atomically and drops output and forwarded traffic per family', () => {
    const rules = egressRuleset(['203.0.113.8', '2001:db8::5']);
    expect(rules.split('\n').slice(0, 3)).toEqual([
      `table inet ${EGRESS_TABLE}`,
      `delete table inet ${EGRESS_TABLE}`,
      `table inet ${EGRESS_TABLE} {`,
    ]);
    expect(rules).toContain('set c2_v4 { type ipv4_addr; elements = { 203.0.113.8 } }');
    expect(rules).toContain('set c2_v6 { type ipv6_addr; elements = { 2001:db8::5 } }');
    expect(rules).toContain('type filter hook output priority -1; policy accept;');
    expect(rules).toContain('type filter hook forward priority -1; policy accept;');
  });

  it('writes an empty set without an elements clause, which nft rejects', () => {
    expect(egressRuleset([])).toContain('set c2_v6 { type ipv6_addr; }');
  });
});

describe('ss parsing', () => {
  it('reads peers, ports and the owning process, v4 and v6', () => {
    const conns = parseSs([
      'ESTAB      0      0      10.0.0.5:44312     203.0.113.8:443   users:(("curl",pid=1234,fd=3))',
      'SYN-SENT   0      1      [2001:db8::1]:51000 [2001:db8::5]:443 users:(("python3",pid=99,fd=7))',
      'ESTAB      0      0      23.95.228.174:443  17.166.21.242:48198',
    ].join('\n'));
    expect(conns).toEqual([
      { state: 'ESTAB', localPort: 44312, peerIp: '203.0.113.8', peerPort: 443, process: 'curl', pid: 1234 },
      { state: 'SYN-SENT', localPort: 51000, peerIp: '2001:db8::5', peerPort: 443, process: 'python3', pid: 99 },
      { state: 'ESTAB', localPort: 443, peerIp: '17.166.21.242', peerPort: 48198, process: null, pid: null },
    ]);
    expect([...parseListeningPorts('LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 [::]:22 [::]:*\n')]).toEqual([443, 22]);
  });
});

function worker(over: Partial<{ block: boolean; enforcing: boolean; ss: string; fetchFail: boolean }> = {}) {
  const events: ThreatEvent[] = [];
  const calls: { cmd: string; args: string[]; input?: string }[] = [];
  const logs: string[] = [];
  let now = Date.parse('2026-10-17T06:00:00Z');
  const feeds = new ThreatFeeds({
    settings: { ...threatFeedSettings({ block: over.block }), allow: [] },
    enforcing: over.enforcing ?? true,
    cachePath: join(mkdtempSync(join(tmpdir(), 'tc-feeds-')), 'threat-feeds.json'),
    bus: { publish: (e) => events.push(e), announceModule: () => {} },
    log: (l) => logs.push(l),
    now: () => now,
    fetchImpl: async (url) => {
      if (over.fetchFail) throw new Error('offline');
      if (url.includes('export/json')) return new Response(THREATFOX);
      if (url.includes('hostfile')) return new Response('127.0.0.1 bad.example\n');
      return new Response('# empty\n');
    },
    run: (cmd, args, input) => {
      calls.push({ cmd, args, input });
      if (cmd === 'ss' && args[0] === '-ltnH') return 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n';
      if (cmd === 'ss') return over.ss ?? '';
      if (cmd === 'nft' && args[0] === 'list') return null; // no table yet
      return '';
    },
  });
  return { feeds, events, calls, logs, advance: (ms: number) => { now += ms; } };
}

describe('ThreatFeeds worker', () => {
  const ss = [
    'ESTAB 0 0 10.0.0.5:44312 203.0.113.8:443 users:(("curl",pid=1234,fd=3))',
    // A listed IP connecting *in* to our :443 is not this box calling out.
    'ESTAB 0 0 10.0.0.5:443 198.51.100.9:55555 users:(("nginx",pid=10,fd=9))',
  ].join('\n');

  it('flags an outbound connection to a listed IP once per hour, never an inbound one', async () => {
    const w = worker({ ss });
    await w.feeds.refresh();
    w.feeds.pollConnections();
    w.feeds.pollConnections();
    expect(w.events).toHaveLength(1);
    expect(w.events[0]).toMatchObject({ module: 'threat-feeds', severity: 'critical' });
    // The remote end must never reach auto-defence as an attacker to ban.
    expect(w.events[0].source_ip).toBeUndefined();
    expect(w.events[0].message).toBe('Outbound connection to known QakBot C2 203.0.113.8:443 by curl (pid 1234)');
    w.advance(3_600_001);
    w.feeds.pollConnections();
    expect(w.events).toHaveLength(2);
  });

  it('loads the egress table only when block is on and remediation enforces', async () => {
    const on = worker({ block: true, enforcing: true });
    await on.feeds.refresh();
    const load = on.calls.find((c) => c.cmd === 'nft' && c.args.join(' ') === '-f -');
    expect(load?.input).toContain('203.0.113.8');
    expect(load?.input).not.toContain('104.21.3.4'); // Cloudflare never makes it in

    const dry = worker({ block: true, enforcing: false });
    await dry.feeds.refresh();
    expect(dry.calls.some((c) => c.cmd === 'nft' && c.args[0] === '-f')).toBe(false);

    const off = worker({ block: false });
    off.feeds.start();
    off.feeds.stop();
    expect(off.calls.some((c) => c.cmd === 'nft' && c.args[0] === '-f')).toBe(false);
  });

  it('keeps the previous list when every feed fails rather than treating silence as all-clear', async () => {
    const w = worker({ fetchFail: true });
    await w.feeds.refresh();
    expect(w.logs.at(-1)).toMatch(/refresh failed, keeping previous list/);
    expect(readFeedCache(join(tmpdir(), 'nope.json'))).toBeNull();
  });
});
