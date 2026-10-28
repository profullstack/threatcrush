import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FirewallAdapter } from '../firewall/adapters.js';
import type { ThreatEvent } from '../../types/events.js';

const store = new Map<string, unknown>();
vi.mock('../../core/state.js', () => ({
  getModuleState: (m: string, k: string) => store.get(`${m}/${k}`),
  setModuleState: (m: string, k: string, v: unknown) => { store.set(`${m}/${k}`, JSON.parse(JSON.stringify(v))); },
  insertEvent: () => {},
}));

const { RemediationManager, isSuccessfulAuth } = await import('../firewall/remediation.js');
const { EventBus } = await import('../event-bus.js');
const { LogWatcher } = await import('../watchers/log-watcher.js');
const { sshdLineFromJournal } = await import('../watchers/journal-watcher.js');
const { SshIntrusionWatch, parseKeyLoginsByFingerprint } = await import('../workers/ssh-intrusion.js');
const { TorExitList, parseTorExitList } = await import('../../core/tor-exits.js');
const { sshdPeerIp, parseAcceptedLogin } = await import('../../core/log-parser.js');
const { classifyAsn, parseCymruOrigin, parseCymruName, cymruOriginName } = await import('../../core/asn.js');

/**
 * Recorded from dev2's /var/log/auth.log during the 2026-10-26/27 intrusion.
 * The key fingerprints are the (since revoked) stolen key and the planted one.
 */
const TOR_LOGIN = '2026-10-26T23:59:14.410317+00:00 dev2 sshd-session[1318075]: Accepted publickey for anthony from 185.129.61.4 port 65366 ssh2: ED25519 SHA256:2Iw+DRKRDjZiwHnYwza6WufCjkxijD+RqW3EzhoJUcg';
const TOR_DISCONNECT = '2026-10-26T23:59:15.800095+00:00 dev2 sshd-session[1320364]: Disconnected from user anthony 185.129.61.4 port 65366';
const TOR_INVALID = '2026-10-25T18:45:29.065240+00:00 dev2 sshd-session[118881]: Invalid user audit-i15127 from 185.129.61.129 port 36196';
const TOR_TIMEOUT = '2026-10-25T18:46:31.221401+00:00 dev2 sshd[330876]: Timeout before authentication for connection from 185.129.61.129 to 23.95.228.174, pid = 118881';
const TOR_PREAUTH = '2026-10-27T00:03:01.000000+00:00 dev2 sshd-session[1500000]: Connection closed by 185.129.61.4 port 41234 [preauth]';
const GCP_LOGIN = '2026-10-27T04:43:10.000000+00:00 dev2 sshd-session[1600000]: Accepted publickey for root from 35.241.182.141 port 51022 ssh2: ED25519 SHA256:2Iw+DRKRDjZiwHnYwza6WufCjkxijD+RqW3EzhoJUcg';

const TOR_EXITS = ['185.129.61.4', '185.129.61.129', ...Array.from({ length: 200 }, (_, i) => `198.51.100.${i % 250}`)];

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

function setup(opts: {
  dry_run?: boolean;
  block_tor_ssh?: boolean;
  allowlist?: string[];
  operatorJournal?: string;
  livePeers?: string[];
} = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tc-intrusion-'));
  const bus = new EventBus();
  const adapter = new FakeAdapter();
  const manager = new RemediationManager(
    adapter,
    bus,
    {
      dry_run: opts.dry_run ?? true,
      allowlist: opts.allowlist ?? [],
      ...(opts.block_tor_ssh === undefined ? {} : { block_tor_ssh: opts.block_tor_ssh }),
    },
    async () => null,
    {
      sshPeers: () => opts.livePeers ?? [],
      moshClients: () => [],
      keyLoginJournal: async () => opts.operatorJournal ?? '',
      automationKeys: () => new Set(),
    },
  );
  const tor = new TorExitList({ cachePath: join(dir, 'tor-exits.txt'), fetchImpl: async () => ({ ok: false, status: 503, text: async () => '' }) });
  tor.load(TOR_EXITS);
  const events: ThreatEvent[] = [];
  bus.on('event', (e: ThreatEvent) => {
    events.push(e);
    if (e.module !== 'firewall-rules') void manager.handleDetection(e);
  });
  const watch = new SshIntrusionWatch({
    bus,
    manager,
    tor,
    historyPath: join(dir, 'key-logins.json'),
    log: () => {},
    asn: { lookup: async () => null },
    io: { readFile: () => null, readDir: () => null, exists: () => false },
    run: () => '',
  });
  // start() would fetch the real list; wire the same pieces by hand.
  manager.setTorExitCheck((ip) => tor.has(ip));
  bus.on('sshd', (line) => { watch.checkTorLine(line); });
  const logWatcher = new LogWatcher(bus) as unknown as {
    process(line: string, src: { path: string; module: string; category: string }): void;
  };
  const feed = (line: string) => logWatcher.process(line, { path: '/var/log/auth.log', module: 'ssh-guard', category: 'auth' });
  const settle = () => new Promise((r) => setTimeout(r, 20));
  return { bus, adapter, manager, events, feed, settle, watch, dir };
}

beforeEach(() => store.clear());

describe('SSH from a Tor exit (recorded dev2 lines)', () => {
  it('bans a Tor exit that LOGGED IN with a key, at once, even in dry_run', async () => {
    const t = setup({ dry_run: true });
    t.feed(TOR_LOGIN);
    await t.settle();
    const tor = t.events.find((e) => e.details?.rule_id === 'ssh-from-tor');
    expect(tor?.severity).toBe('critical');
    expect(tor?.source_ip).toBe('185.129.61.4');
    expect(tor?.message).toContain('LOGGED IN as anthony');
    expect(t.adapter.blocked.has('185.129.61.4')).toBe(true);
    const entry = t.manager.getBlocklist().find((b) => b.ip === '185.129.61.4');
    expect(entry?.dry_run).toBe(false);
    expect(entry?.strict).toBe(true);
    // max_ban (7d default), not the 5-minute first rung
    expect((entry!.expires_at - entry!.blocked_at) / 1000).toBe(7 * 86400);
  });

  it.each([TOR_INVALID, TOR_TIMEOUT, TOR_PREAUTH, TOR_DISCONNECT])('bans on any sshd line naming the exit: %s', async (line) => {
    const t = setup();
    t.feed(line);
    await t.settle();
    const ip = sshdPeerIp(line.split(': ').slice(1).join(': '))!;
    expect(t.adapter.blocked.has(ip)).toBe(true);
  });

  it('bans even when the exit was remembered as an operator from the journal (the dev2 trap)', async () => {
    const journal = `${Date.now() / 1000 - 3600} dev2 sshd-session[1]: Accepted publickey for anthony from 185.129.61.4 port 65366 ssh2: ED25519 SHA256:2Iw+DRKRDjZiwHnYwza6WufCjkxijD+RqW3EzhoJUcg\n`;
    const t = setup({ operatorJournal: journal, livePeers: ['185.129.61.4'] });
    await t.manager.seedOperatorsFromJournal();
    expect(t.manager.getOperators()['185.129.61.4']).toBeUndefined();
    expect(t.manager.isAllowlisted('185.129.61.4')).toBe(false);
    t.feed(TOR_LOGIN);
    await t.settle();
    expect(t.adapter.blocked.has('185.129.61.4')).toBe(true);
  });

  it('a live session from the exit does not lift its ban', async () => {
    const t = setup({ livePeers: ['185.129.61.4'] });
    t.feed(TOR_LOGIN);
    await t.settle();
    // the expiry sweep refreshes live-session protection every 10s
    await (t.manager as unknown as { processExpiries(): Promise<void> }).processExpiries();
    expect(t.adapter.blocked.has('185.129.61.4')).toBe(true);
  });

  it('never bans one of our own addresses, even if it shows up on the Tor list', async () => {
    const t = setup({ allowlist: ['185.129.61.0/24'] });
    t.feed(TOR_LOGIN);
    await t.settle();
    expect(t.adapter.blocked.size).toBe(0);
    expect(t.events.find((e) => e.details?.rule_id === 'ssh-from-tor')).toBeUndefined();
  });

  it('with block_tor_ssh = false it alerts but does not ban', async () => {
    const t = setup({ block_tor_ssh: false });
    t.feed(TOR_INVALID);
    await t.settle();
    const tor = t.events.find((e) => e.details?.rule_id === 'ssh-from-tor');
    expect(tor?.severity).toBe('high');
    expect(tor?.details?.remediation).toBeUndefined();
    expect(t.adapter.blocked.size).toBe(0);
  });

  it('a non-Tor key login is still never a ban (the 2026-09-25 self-ban stays fixed)', async () => {
    const t = setup({ dry_run: false });
    t.feed(GCP_LOGIN);
    await t.settle();
    expect(t.adapter.blocked.size).toBe(0);
    expect(isSuccessfulAuth('SSH login accepted for root')).toBe(true);
  });

  it('a ban enforced in dry_run is re-applied after a restart', async () => {
    const t = setup({ dry_run: true });
    t.feed(TOR_LOGIN);
    await t.settle();
    const adapter2 = new FakeAdapter();
    const m2 = new RemediationManager(adapter2, t.bus, { dry_run: true }, async () => null, {
      sshPeers: () => [], moshClients: () => [], keyLoginJournal: async () => '', automationKeys: () => new Set(),
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(adapter2.blocked.has('185.129.61.4')).toBe(true);
    m2.stop();
  });
});

describe('Tor exit list', () => {
  it('parses the bulk exit list and keeps a good copy when a download is broken', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tc-tor-'));
    const cachePath = join(dir, 'tor-exits.txt');
    let body = TOR_EXITS.join('\n');
    const list = new TorExitList({ cachePath, fetchImpl: async () => ({ ok: true, status: 200, text: async () => body }) });
    expect(await list.refresh()).toBe(true);
    expect(list.has('185.129.61.4')).toBe(true);
    expect(list.has('::ffff:185.129.61.129')).toBe(true);
    expect(existsSync(cachePath)).toBe(true);
    body = '1.2.3.4\n';
    expect(await list.refresh()).toBe(false);
    expect(list.size).toBe(parseTorExitList(TOR_EXITS.join('\n')).size);
    const fresh = new TorExitList({ cachePath });
    expect(fresh.loadCache()).toBe(true);
    expect(fresh.has('185.129.61.4')).toBe(true);
    expect(readFileSync(cachePath, 'utf-8')).toContain('185.129.61.129');
  });
});

describe('sshd line parsing', () => {
  it('finds the peer in every sshd message shape', () => {
    expect(sshdPeerIp('Timeout before authentication for connection from 185.129.61.129 to 23.95.228.174, pid = 118881')).toBe('185.129.61.129');
    expect(sshdPeerIp('Disconnected from user anthony 185.129.61.4 port 65366')).toBe('185.129.61.4');
    expect(sshdPeerIp('drop connection #0 from [185.129.61.4]:41234 on [23.95.228.174]:22 penalty: failed authentication')).toBe('185.129.61.4');
    expect(sshdPeerIp('Connection closed by 2001:db8::7 port 22 [preauth]')).toBe('2001:db8::7');
    expect(sshdPeerIp('Server listening on 0.0.0.0 port 22.')).toBe('0.0.0.0');
    expect(sshdPeerIp('pam_unix(sshd:session): session closed for user anthony')).toBeNull();
  });

  it('reads the key fingerprint of an accepted login', () => {
    expect(parseAcceptedLogin('Accepted publickey for anthony from 185.129.61.4 port 65366 ssh2: ED25519 SHA256:2Iw+DRKRDjZiwHnYwza6WufCjkxijD+RqW3EzhoJUcg')).toEqual({
      method: 'publickey', user: 'anthony', ip: '185.129.61.4', port: 65366, key_type: 'ED25519', fingerprint: 'SHA256:2Iw+DRKRDjZiwHnYwza6WufCjkxijD+RqW3EzhoJUcg',
    });
  });

  it('turns a journal record into the same sshd line', () => {
    const line = sshdLineFromJournal({ _UID: '0', _COMM: 'sshd-session', MESSAGE: 'Invalid user audit-i15127 from 185.129.61.129 port 36196' });
    expect(line?.ip).toBe('185.129.61.129');
    expect(sshdLineFromJournal({ _UID: '1000', _COMM: 'logger', MESSAGE: 'Invalid user x from 185.129.61.129 port 1' })).toBeNull();
  });
});

describe('key login from a never-seen address', () => {
  const FP = 'SHA256:a0Dp+uBHL50r3kelVWCyKfONRKFooMi+isYCLjLgnR0';
  const keyLogin = (ip: string, user = 'anthony', fp = FP): ThreatEvent => ({
    timestamp: new Date(), module: 'ssh-guard', category: 'auth', severity: 'info',
    message: `SSH login accepted for ${user}`, source_ip: ip,
    details: { ssh_user: user, auth_method: 'publickey', fingerprint: fp, key_type: 'ED25519' },
  });

  function watchWith(asn: Record<string, { asn: number; name: string }>, keys = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMm anthony@profullstack-2026-10-28\n`, allowlist: string[] = []) {
    const dir = mkdtempSync(join(tmpdir(), 'tc-keylogin-'));
    const historyPath = join(dir, 'key-logins.json');
    writeFileSync(historyPath, JSON.stringify({ [FP]: { '172.12.140.170': { first: 'x', last: 'x', count: 3 } } }));
    const bus = new EventBus();
    const events: ThreatEvent[] = [];
    bus.on('event', (e: ThreatEvent) => events.push(e));
    const tor = new TorExitList({ cachePath: join(dir, 't'), fetchImpl: async () => ({ ok: false, status: 500, text: async () => '' }) });
    tor.load(TOR_EXITS);
    const watch = new SshIntrusionWatch({
      bus,
      manager: { blockTorSsh: true, isFleetAddress: (ip: string) => allowlist.includes(ip), setTorExitCheck: () => {} },
      tor,
      historyPath,
      log: () => {},
      asn: { lookup: async (ip: string) => (asn[ip] ? { ...asn[ip] } : null) },
      io: {
        readFile: (p: string) => (p === '/etc/passwd' ? 'anthony:x:1001:1003::/home/anthony:/bin/zsh\n' : p === '/home/anthony/.ssh/authorized_keys' ? keys : null),
        readDir: () => null,
        exists: () => false,
      },
      run: () => '',
    });
    (watch as unknown as { loadHistory(): void }).loadHistory();
    return { watch, events };
  }

  it('alerts high for a person\'s key from Google Cloud (35.241.182.141, the planted-key host)', async () => {
    const { watch } = watchWith({ '35.241.182.141': { asn: 396982, name: 'GOOGLE-CLOUD-PLATFORM - Google LLC, US' } });
    const out = await watch.checkKeyLogin(keyLogin('35.241.182.141'));
    expect(out?.severity).toBe('high');
    expect(out?.details?.rule_id).toBe('ssh-human-key-hosting-login');
    expect(out?.message).toContain('35.241.182.141');
    expect(out?.message).toContain('AS396982');
    expect(out?.details?.fingerprint).toBe(FP);
    expect(out?.source_ip).toBeUndefined();
  });

  it('alerts high for a never-seen ISP address, and only once', async () => {
    const { watch } = watchWith({ '73.1.2.3': { asn: 7922, name: 'COMCAST-7922, US' } });
    const first = await watch.checkKeyLogin(keyLogin('73.1.2.3'));
    expect(first?.details?.rule_id).toBe('ssh-key-new-ip');
    expect(first?.severity).toBe('high');
    expect(await watch.checkKeyLogin(keyLogin('73.1.2.3'))).toBeNull();
  });

  it('is quiet for a known address and for our own boxes', async () => {
    const { watch } = watchWith({}, undefined, ['23.95.228.174']);
    expect(await watch.checkKeyLogin(keyLogin('172.12.140.170'))).toBeNull();
    expect(await watch.checkKeyLogin(keyLogin('23.95.228.174'))).toBeNull();
  });

  it('treats a CI deploy key from GitHub Actions (Azure) as expected', async () => {
    const DEPLOY = 'SHA256:XFpNTjYTzFPV4s6VsmAhDhSKgj5OlVddbz6+6zzZS1w';
    const keys = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMm github-actions-deploy@nichedb\n';
    const { watch } = watchWith({ '172.183.157.185': { asn: 8075, name: 'MICROSOFT-CORP-MSN-AS-BLOCK, US' } }, keys);
    // the comment lookup is by fingerprint: make the fixture key's fingerprint the deploy one
    (watch as unknown as { keyComments: { at: number; byFp: Map<string, { user: string; comment: string }> } }).keyComments = {
      at: Date.now(), byFp: new Map([[DEPLOY, { user: 'anthony', comment: 'github-actions-deploy@nichedb' }]]),
    };
    const out = await watch.checkKeyLogin(keyLogin('172.183.157.185', 'anthony', DEPLOY));
    expect(out?.severity).toBe('info');
  });

  it('learns a 30-day baseline from the journal, but never a Tor exit', () => {
    const j = [
      '1793000000.1 dev2 sshd-session[1]: Accepted publickey for anthony from 172.12.140.170 port 1 ssh2: ED25519 SHA256:aaa',
      '1793000001.1 dev2 sshd-session[2]: Accepted publickey for anthony from 185.129.61.4 port 2 ssh2: ED25519 SHA256:aaa',
    ].join('\n');
    const parsed = parseKeyLoginsByFingerprint(j);
    expect([...parsed.get('SHA256:aaa')!.keys()]).toEqual(['172.12.140.170', '185.129.61.4']);
  });
});

describe('ASN classification', () => {
  it('reads Team Cymru answers', () => {
    expect(cymruOriginName('35.241.182.141')).toBe('141.182.241.35.origin.asn.cymru.com');
    expect(parseCymruOrigin('396982 | 35.241.176.0/20 | US | arin | 2017-09-29')).toEqual({ asn: 396982, prefix: '35.241.176.0/20', country: 'US' });
    expect(parseCymruName('16276 | FR | ripencc | 2004-01-26 | OVH, FR')).toBe('OVH, FR');
  });

  it('classifies the intrusion networks', () => {
    expect(classifyAsn({ asn: 16276, name: 'OVH, FR' })).toBe('hosting');
    expect(classifyAsn({ asn: 396982, name: 'GOOGLE-CLOUD-PLATFORM - Google LLC, US' })).toBe('hosting');
    expect(classifyAsn({ asn: 8075, name: 'MICROSOFT-CORP-MSN-AS-BLOCK, US' })).toBe('ci');
    expect(classifyAsn({ asn: 9009, name: 'M247, GB' })).toBe('vpn');
    expect(classifyAsn({ asn: 7018, name: 'ATT-INTERNET4, US' })).toBe('unknown');
  });
});

describe('Lightning channel closes (recorded dev2 cln.log, 2026-10-27)', async () => {
  const { ChannelCloseDetector } = await import('../workers/lightning-watch.js');
  const LINES = [
    '2026-10-27T07:31:58.420Z INFO    03142b162b4e55237e49dc8aadf919c99eface419c21869339687f365c93675886-chan#3: State changed from CHANNELD_NORMAL to CHANNELD_SHUTTING_DOWN',
    '2026-10-27T07:32:03.425Z INFO    03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f-chan#1: State changed from CHANNELD_NORMAL to CHANNELD_SHUTTING_DOWN',
    '2026-10-27T07:32:03.857Z INFO    03cf9e223a45bccb551a36965da385441efb525645e8490e144c5797f7a597481f-chan#6: State changed from CHANNELD_NORMAL to CHANNELD_SHUTTING_DOWN',
    '2026-10-27T07:44:08.469Z INFO    03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f-chan#1: State changed from CLOSINGD_COMPLETE to FUNDING_SPEND_SEEN',
  ];

  it('one close is high; the second within 10 minutes is a critical burst, raised once', () => {
    const d = new ChannelCloseDetector();
    const out = LINES.map((l) => d.feed(l));
    expect(out[0].map((e) => e.severity)).toEqual(['high']);
    expect(out[1].map((e) => e.severity)).toEqual(['high', 'critical']);
    expect(out[1][1].details?.rule_id).toBe('ln-channel-close-burst');
    expect(out[2].map((e) => e.severity)).toEqual(['high']);
    expect(out[3]).toEqual([]);
  });
});
