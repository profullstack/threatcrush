import { describe, it, expect } from 'vitest';
import type { ThreatEvent } from '../../types/events.js';
import { keyFingerprint } from '../../core/privileges/index.js';
import { classifySshdMessage, SshAuthHistory } from '../ssh-context/auth-history.js';
import { AuthorizedKeysIndex, maskBlob, type KeyFilesIO } from '../ssh-context/authorized-keys.js';
import {
  classifyAddress, cymruOriginName, GitHubActionsRanges, NetLookup, parseCymruAsName, parseCymruOrigin, type RangesDeps,
} from '../ssh-context/ip-intel.js';
import { findCiDeploy, parseCiDeployJournal, parseCiDeployMessage, pickCiDeploy, redactCommand } from '../ssh-context/ci-deploy.js';
import { SshLoginEnricher, sshContextSettings, isAcceptedLogin } from '../ssh-context/index.js';
import { evidenceOf, RuleEngine } from '../rules/engine.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { uploadSeverity } from '../workers/cloud-sync.js';

// Documentation ranges only (RFC 5737).
const RUNNER = '192.0.2.10';
const SCANNER_A = '198.51.100.7';
const SCANNER_B = '203.0.113.9';
const AT = Date.parse('2026-11-22T03:58:33Z');

const blob = (seed: string) => Buffer.from(`fixture-ed25519-public-key-${seed}`).toString('base64');
const DEPLOY_BLOB = blob('deploy');
const DEPLOY_FP = keyFingerprint(DEPLOY_BLOB)!;
const PLANTED_BLOB = blob('planted');
const PLANTED_FP = keyFingerprint(PLANTED_BLOB)!;

const PASSWD = [
  'root:x:0:0:root:/root:/bin/bash',
  'deploy:x:1000:1000::/home/deploy:/bin/bash',
  'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
].join('\n');

const FILES: Record<string, string> = {
  '/home/deploy/.ssh/authorized_keys': [
    '# deploy keys',
    `restrict,command="/home/deploy/.local/bin/ci-deploy example/app" ssh-ed25519 ${DEPLOY_BLOB} deploy@example/app-2026-11-20`,
    `ssh-ed25519 ${PLANTED_BLOB} ci-diag-20261120`,
  ].join('\n'),
  '/root/.ssh/authorized_keys': `ssh-ed25519 ${PLANTED_BLOB} ci-diag-20261120\n`,
};

const fakeIO = (files = FILES): KeyFilesIO => ({
  passwd: () => PASSWD,
  mtime: (p) => (p in files ? 1 : null),
  read: (p) => files[p] ?? null,
});

const line = (sec: number, message: string, ip: string) => ({ timestamp: new Date(AT + sec * 1000), message, ip });

describe('classifySshdMessage', () => {
  it('reads failures, invalid users, preauth closes and session closes', () => {
    expect(classifySshdMessage(`Failed password for root from ${SCANNER_A} port 40000 ssh2`)).toEqual({ kind: 'failed', user: 'root', port: 40000 });
    expect(classifySshdMessage(`Failed password for invalid user admin from ${SCANNER_A} port 40001 ssh2`)).toEqual({ kind: 'failed', user: 'admin', port: 40001 });
    expect(classifySshdMessage(`Invalid user oracle from ${SCANNER_B} port 5555`)).toEqual({ kind: 'invalid', user: 'oracle', port: 5555 });
    expect(classifySshdMessage(`Connection closed by authenticating user root ${SCANNER_B} port 6000 [preauth]`)).toEqual({ kind: 'preauth-close', user: 'root', port: 6000 });
    expect(classifySshdMessage(`Disconnected from user deploy ${RUNNER} port 33792`)).toEqual({ kind: 'close', user: 'deploy', port: 33792 });
    expect(classifySshdMessage(`Accepted publickey for deploy from ${RUNNER} port 33792 ssh2: ED25519 ${DEPLOY_FP}`)).toBeNull();
  });
});

describe('SshAuthHistory', () => {
  it('counts failures before a login and says they came from other addresses', () => {
    const h = new SshAuthHistory(() => AT);
    h.record(line(-500, `Invalid user admin from ${SCANNER_A} port 40001`, SCANNER_A));
    h.record(line(-499, `Failed password for invalid user admin from ${SCANNER_A} port 40001 ssh2`, SCANNER_A));
    h.record(line(-498, `Connection closed by invalid user admin ${SCANNER_A} port 40001 [preauth]`, SCANNER_A));
    h.record(line(-300, `Failed password for root from ${SCANNER_A} port 40002 ssh2`, SCANNER_A));
    h.record(line(-300, `Failed password for root from ${SCANNER_A} port 40002 ssh2`, SCANNER_A)); // same line twice (auth.log + journal)
    h.record(line(-100, `Invalid user oracle from ${SCANNER_B} port 5555`, SCANNER_B));
    h.record(line(-5000, `Failed password for root from ${RUNNER} port 1 ssh2`, RUNNER)); // outside the window
    const f = h.failuresBefore(AT, RUNNER, 600);
    expect(f.total).toBe(3);
    expect(f.same_ip).toBe(0);
    expect(f.other_ips).toBe(3);
    expect(f.ips).toEqual([{ ip: SCANNER_A, count: 2 }, { ip: SCANNER_B, count: 1 }]);
    expect(f.users?.map((u) => u.user).sort()).toEqual(['admin', 'oracle', 'root']);
  });

  it('counts every failed try in one connection from the address that then got in', () => {
    const h = new SshAuthHistory(() => AT);
    for (let i = 0; i < 3; i++) h.record(line(-60 + i, `Failed password for deploy from ${RUNNER} port 41000 ssh2`, RUNNER));
    expect(h.failuresBefore(AT, RUNNER).same_ip).toBe(3);
  });

  it('finds the session close by address and client port', () => {
    const h = new SshAuthHistory(() => AT);
    h.record(line(41, `Disconnected from user deploy ${RUNNER} port 33792`, RUNNER));
    expect(h.closeOf(RUNNER, 33792, AT)).toBe(AT + 41_000);
    expect(h.closeOf(RUNNER, 1, AT)).toBeNull();
  });
});

describe('AuthorizedKeysIndex', () => {
  const idx = new AuthorizedKeysIndex(fakeIO());

  it('resolves a fingerprint to its line, options and comment, with the blob masked', () => {
    const k = idx.lookup(DEPLOY_FP);
    expect(k.found).toBe(true);
    expect(k.command).toBe('/home/deploy/.local/bin/ci-deploy example/app');
    expect(k.restrict).toBe(true);
    expect(k.options).toEqual(['restrict', 'command="/home/deploy/.local/bin/ci-deploy example/app"']);
    expect(k.comment).toBe('deploy@example/app-2026-11-20');
    expect(k.files).toEqual(['/home/deploy/.ssh/authorized_keys:2']);
    expect(k.in_root_and_user).toBe(false);
    expect(k.suspicious_comment).toBe(false);
    expect(k.line_masked).toContain(maskBlob(DEPLOY_BLOB));
    expect(JSON.stringify(k)).not.toContain(DEPLOY_BLOB);
  });

  it('flags a key in root and a user file with a dated diag comment', () => {
    const k = idx.lookup(PLANTED_FP);
    expect(k.in_root_and_user).toBe(true);
    expect(k.suspicious_comment).toBe(true);
    expect(k.accounts?.sort()).toEqual(['deploy', 'root']);
    expect(k.options).toEqual([]);
  });

  it('says when the key is not in any readable file, and marks expected keys', () => {
    expect(idx.lookup('SHA256:nothere')).toEqual({ found: false, fingerprint: 'SHA256:nothere' });
    expect(idx.lookup(DEPLOY_FP, new Set([DEPLOY_FP])).expected).toBe(true);
  });
});

describe('ip-intel', () => {
  const ranges = (cidrs: string[]): RangesDeps => ({ fetchJson: async () => ({ actions: cidrs }), load: () => null, save: () => {}, now: () => AT });

  it('classifies loopback, own, Tailscale, private, GitHub Actions and public', async () => {
    const gh = new GitHubActionsRanges(ranges(['192.0.2.0/24']));
    await gh.refresh();
    const c = { own: () => new Set(['203.0.113.50']), isGitHubActions: (ip: string) => gh.has(ip) };
    expect(classifyAddress('127.0.0.1', c)).toBe('loopback');
    expect(classifyAddress('::ffff:127.0.0.1', c)).toBe('loopback');
    expect(classifyAddress('203.0.113.50', c)).toBe('self');
    expect(classifyAddress('100.100.1.2', c)).toBe('tailscale');
    expect(classifyAddress('10.1.2.3', c)).toBe('private');
    expect(classifyAddress(RUNNER, c)).toBe('github-actions');
    expect(classifyAddress(SCANNER_A, c)).toBe('public');
  });

  it('keeps the last good ranges when a refresh fails', async () => {
    let fail = false;
    let now = AT;
    const deps: RangesDeps = { fetchJson: async () => { if (fail) throw new Error('down'); return { actions: ['192.0.2.0/24'] }; }, load: () => null, save: () => {}, now: () => now };
    const gh = new GitHubActionsRanges(deps);
    await gh.refresh();
    fail = true;
    now += 2 * 24 * 3600_000;
    await gh.refresh();
    expect(gh.has(RUNNER)).toBe(true);
  });

  it('builds and parses Team Cymru answers', async () => {
    expect(cymruOriginName('192.0.2.10')).toBe('10.2.0.192.origin.asn.cymru.com');
    expect(cymruOriginName('2001:db8::1')).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com');
    expect(parseCymruOrigin('64500 | 192.0.2.0/24 | US | arin | 2017-10-18')).toEqual({ asn: 64500, country: 'US' });
    expect(parseCymruAsName('64500 | US | arin | 2000-06-12 | EXAMPLE-NET, US')).toBe('EXAMPLE-NET');
    const net = new NetLookup({
      reverse: async () => ['runner.example.net'],
      txt: async (name) => (name.startsWith('AS') ? [['64500 | US | arin | 2000-06-12 | EXAMPLE-NET, US']] : [['64500 | 192.0.2.0/24 | US | arin | 2017-10-18']]),
    });
    expect(await net.lookup(RUNNER)).toEqual({ rdns: 'runner.example.net', asn: 64500, as_org: 'EXAMPLE-NET', country: 'US' });
  });

  it('gives up on a slow lookup instead of waiting', async () => {
    const net = new NetLookup({ reverse: () => new Promise(() => {}), txt: () => new Promise(() => {}) }, 20);
    expect(await net.lookup(RUNNER)).toEqual({ rdns: null, asn: null, as_org: null, country: null });
  });
});

describe('ci-deploy', () => {
  const journal = [
    `${AT / 1000 + 1}.000000 web-1 ci-deploy[4242]: ALLOW (deploy app 5addb4f2) repo=example/app from=${RUNNER} cmd=/srv/deploy-app.sh 5addb4f2`,
    `${AT / 1000 + 2}.000000 web-1 ci-deploy[4243]: DENY (not allowlisted) repo=example/other from=${SCANNER_A} cmd=sh -c id`,
    `${AT / 1000 + 3}.000000 web-1 sshd[1]: unrelated`,
  ].join('\n');

  it('parses ALLOW/DENY lines', () => {
    expect(parseCiDeployMessage(`ALLOW (deploy app 5addb4f2) repo=example/app from=${RUNNER} cmd=/srv/deploy-app.sh 5addb4f2`))
      .toEqual({ decision: 'ALLOW', action: 'deploy app 5addb4f2', repo: 'example/app', from: RUNNER, command: '/srv/deploy-app.sh 5addb4f2' });
    expect(parseCiDeployJournal(journal)).toHaveLength(2);
  });

  it('picks the line from the login address near the login time', () => {
    expect(pickCiDeploy(parseCiDeployJournal(journal), RUNNER, AT)).toMatchObject({ decision: 'ALLOW', repo: 'example/app' });
    expect(pickCiDeploy(parseCiDeployJournal(journal), SCANNER_B, AT)).toBeNull();
  });

  it('redacts secret-looking values in the command', () => {
    expect(redactCommand('deploy.sh API_TOKEN=abc123 --password=hunter2 sha=5addb4f2')).toBe('deploy.sh API_TOKEN=[redacted] --password=[redacted] sha=5addb4f2');
  });

  it('queries journalctl for the tag around the login', async () => {
    let args: string[] = [];
    const ci = await findCiDeploy(RUNNER, AT, 'ci-deploy', async (a) => { args = a; return journal; });
    expect(args.slice(0, 2)).toEqual(['-t', 'ci-deploy']);
    expect(ci?.action).toBe('deploy app 5addb4f2');
  });
});

function acceptedEvent(ip: string, fp: string, port = 33792): ThreatEvent {
  return {
    timestamp: new Date(AT),
    module: 'ssh-guard',
    category: 'auth',
    severity: 'info',
    message: 'SSH login accepted for deploy',
    source_ip: ip,
    details: { user: 'deploy', ssh_user: 'deploy', auth_method: 'publickey', port, key_type: 'ED25519', fingerprint: fp },
  };
}

function enricher(over: Partial<Parameters<typeof sshContextSettings>[0]> = {}) {
  const gh = new GitHubActionsRanges({ fetchJson: async () => ({ actions: ['192.0.2.0/24'] }), load: () => null, save: () => {}, now: () => AT });
  const e = new SshLoginEnricher(sshContextSettings({ settle_ms: 0, ...over }), {
    keys: new AuthorizedKeysIndex(fakeIO()),
    ranges: gh,
    net: { lookup: async () => ({ rdns: null, asn: 8075, as_org: 'MICROSOFT-CORP-MSN-AS-BLOCK', country: 'US' }) },
    journal: async () => `${AT / 1000 + 1}.000000 web-1 ci-deploy[1]: ALLOW (deploy app 5addb4f2) repo=example/app from=${RUNNER} cmd=/srv/deploy-app.sh 5addb4f2`,
    own: () => new Set(),
    host: 'web-1',
    sleep: async () => {},
    now: () => AT,
  });
  e.recordSshd(line(-200, `Failed password for root from ${SCANNER_A} port 40002 ssh2`, SCANNER_A));
  e.recordSshd(line(41, `Disconnected from user deploy ${RUNNER} port 33792`, RUNNER));
  return e;
}

describe('SshLoginEnricher', () => {
  it('turns the motivating CI deploy into a likely-CI context', async () => {
    const e = enricher();
    const ev = acceptedEvent(RUNNER, DEPLOY_FP);
    expect(isAcceptedLogin(ev) && e.wants(ev)).toBe(true);
    const ctx = (await e.enrich(ev))!;
    expect(ev.details?.ssh_context).toBe(ctx);
    expect(ctx.host).toBe('web-1');
    expect(ctx.source).toEqual({ ip: RUNNER, kind: 'github-actions', rdns: null, asn: 8075, as_org: 'MICROSOFT-CORP-MSN-AS-BLOCK', country: 'US' });
    expect(ctx.key?.command).toContain('ci-deploy example/app');
    expect(ctx.failures).toMatchObject({ total: 1, same_ip: 0, other_ips: 1 });
    expect(ctx.session).toMatchObject({ ci_deploy: { decision: 'ALLOW', repo: 'example/app' }, duration_s: 41 });
    expect(ctx.verdict.level).toBe('likely-ci');
    expect(ctx.verdict.summary).toBe('Likely CI deploy: GitHub Actions IP, forced-command deploy key, ci-deploy ALLOW deploy app 5addb4f2');
    expect(JSON.stringify(ctx)).not.toContain(DEPLOY_BLOB);
  });

  it('calls the planted key from a public address suspicious', async () => {
    const ctx = (await enricher().enrich(acceptedEvent(SCANNER_B, PLANTED_FP, 50000)))!;
    expect(ctx.verdict.level).toBe('suspicious');
    expect(ctx.verdict.severity).toBe('critical');
    expect(ctx.session?.open).toBe(true);
    expect(ctx.session?.ci_deploy).toBeUndefined();
  });

  it('collapses an expected key to info', async () => {
    const ctx = (await enricher({ expected_keys: [DEPLOY_FP] }).enrich(acceptedEvent(RUNNER, DEPLOY_FP)))!;
    expect(ctx.verdict).toMatchObject({ level: 'expected', severity: 'info' });
  });

  it('does nothing when disabled', () => {
    expect(enricher({ enabled: false }).wants(acceptedEvent(RUNNER, DEPLOY_FP))).toBe(false);
  });
});

describe('rule engine and upload', () => {
  it('carries ssh_context in the detection evidence', async () => {
    const ev = acceptedEvent(RUNNER, DEPLOY_FP);
    await enricher().enrich(ev);
    const found: Array<{ raw_metadata?: Record<string, unknown> }> = [];
    const engine = new RuleEngine((d) => found.push(d));
    engine.loadRules(DEFAULT_RULES.filter((r) => r.id === 'ssh-success-after-failures'));
    engine.evaluate(ev);
    expect(found).toHaveLength(1);
    const evidence = found[0].raw_metadata?.evidence as Record<string, unknown>;
    expect((evidence.ssh_context as { verdict: { level: string } }).verdict.level).toBe('likely-ci');
    expect(found[0].raw_metadata?.tags).toContain('ssh-login-verdict');
    expect(evidenceOf({ ...ev, details: { ssh_context: { v: 2 } } }).ssh_context).toBeUndefined();
  });

  it('uploads a verdict-lowered detection when the rule severity would have been', () => {
    const base = { timestamp: new Date(), module: 'rule-engine', category: 'auth' as const, message: '[DETECTION] SSH Login Accepted' };
    expect(uploadSeverity({ ...base, severity: 'low', details: { rule_severity: 'critical' } })).toBe('critical');
    expect(uploadSeverity({ ...base, severity: 'low', details: {} })).toBe('low');
  });
});
