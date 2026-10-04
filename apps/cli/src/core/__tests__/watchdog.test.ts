import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';
import {
  WatchdogLog,
  findFinding,
  findingBrief,
  groupFindings,
  isAttack,
  outcomeFor,
  readAttacks,
  readTriage,
  reproCommand,
  setTriage,
  toRecord,
} from '../watchdog.js';

function web(overrides: Partial<ThreatEvent> & { status?: number; url?: string; attack?: string } = {}): ThreatEvent {
  const url = overrides.url ?? "/search?q=1' OR '1'='1";
  const { status = 200, attack = 'sqli', ...rest } = overrides;
  return {
    timestamp: new Date('2026-10-04T10:00:00Z'),
    module: 'log-watcher',
    category: 'web',
    severity: 'high',
    message: `Attack [${attack.toUpperCase()}]: GET ${url}`,
    source_ip: '203.0.113.9',
    details: {
      host: 'example.com',
      path: url.split('?')[0],
      url,
      method: 'GET',
      status,
      attack_type: attack,
      crs_score: 10,
      ua: 'sqlmap/1.8',
    },
    ...rest,
  };
}

describe('isAttack', () => {
  it('keeps CRS-matched web requests, even below the ban threshold', () => {
    expect(isAttack(web())).toBe(true);
    expect(isAttack(web({ severity: 'low' }))).toBe(true);
  });

  it('skips plain 4xx/5xx with no attack signature', () => {
    const e: ThreatEvent = {
      timestamp: new Date(), module: 'log-watcher', category: 'web', severity: 'medium',
      message: 'Server error 502: GET /', details: { status: 502, path: '/' },
    };
    expect(isAttack(e)).toBe(false);
  });

  it('keeps medium+ detections from other modules', () => {
    expect(isAttack({
      timestamp: new Date(), module: 'rule-engine', category: 'auth', severity: 'high',
      message: '[DETECTION] SSH brute force', source_ip: '198.51.100.4', details: { rule_id: 'ssh-brute' },
    })).toBe(true);
  });

  it('skips firewall notices, heartbeats and low-severity chatter', () => {
    expect(isAttack({ timestamp: new Date(), module: 'firewall-rules', category: 'network', severity: 'high', message: 'Banned 1.2.3.4' })).toBe(false);
    expect(isAttack({ timestamp: new Date(), module: 'network-monitor', category: 'network', severity: 'medium', message: 'alive', details: { heartbeat: true } })).toBe(false);
    expect(isAttack({ timestamp: new Date(), module: 'user-journal', category: 'system', severity: 'info', message: 'hello' })).toBe(false);
  });
});

describe('outcomeFor', () => {
  it('maps status classes', () => {
    expect(outcomeFor(200)).toBe('answered');
    expect(outcomeFor(302)).toBe('redirected');
    expect(outcomeFor(403)).toBe('refused');
    expect(outcomeFor(500)).toBe('errored');
    expect(outcomeFor(undefined)).toBe('unknown');
  });
});

describe('toRecord', () => {
  it('falls back to the message for events that predate details.url', () => {
    const e = web();
    delete e.details!.url;
    delete e.details!.method;
    const r = toRecord(e);
    expect(r.method).toBe('GET');
    expect(r.url).toBe("/search?q=1'");
  });

  it('gives repeats of the same endpoint+attack one id, and different endpoints different ids', () => {
    const a = toRecord(web({ url: '/search?q=1' }));
    const b = toRecord(web({ url: '/search?q=2', source_ip: '192.0.2.1' }));
    const c = toRecord(web({ url: '/login?u=1' }));
    expect(a.id).toBe(b.id);
    expect(a.id).not.toBe(c.id);
  });

  it('groups non-web events by message shape, ignoring addresses and counts', () => {
    const msg = (ip: string, n: number) => ({
      timestamp: new Date(), module: 'network-monitor', category: 'network' as const, severity: 'high' as const,
      message: `Port scan from ${ip}: ${n} ports`, source_ip: ip,
    });
    expect(toRecord(msg('1.2.3.4', 12)).id).toBe(toRecord(msg('5.6.7.8', 40)).id);
  });
});

describe('WatchdogLog + triage', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'tc-watchdog-')); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('appends attacks, counts outcomes, and ignores non-attacks', () => {
    const log = new WatchdogLog(dir);
    expect(log.record(web({ status: 200 }))).not.toBeNull();
    expect(log.record(web({ status: 404, timestamp: new Date('2026-10-04T10:00:01Z') }))).not.toBeNull();
    expect(log.record(web({ status: 500, timestamp: new Date('2026-10-04T10:00:02Z') }))).not.toBeNull();
    expect(log.record({ timestamp: new Date(), module: 'x', category: 'system', severity: 'info', message: 'hi' })).toBeNull();
    log.flush();
    expect(log.stats).toEqual({ logged: 3, answered: 1, errored: 1 });
    expect(readAttacks(dir)).toHaveLength(3);
  });

  it('does not log the same event twice, even across a reopen (reconnect backfill)', () => {
    const first = new WatchdogLog(dir);
    first.record(web());
    expect(first.record(web())).toBeNull();
    first.flush();
    const second = new WatchdogLog(dir);
    expect(second.record(web())).toBeNull();
    second.flush();
    expect(readAttacks(dir)).toHaveLength(1);
  });

  it('writes the log owner-only', () => {
    const log = new WatchdogLog(dir);
    log.record(web());
    log.flush();
    expect(statSync(join(dir, 'attacks.jsonl')).mode & 0o777).toBe(0o600);
  });

  it('groups into findings, answered first, and records verdicts', () => {
    const log = new WatchdogLog(dir);
    for (let i = 0; i < 5; i++) {
      log.record(web({ url: '/wp-login.php', attack: 'scanner', status: 404, timestamp: new Date(Date.UTC(2026, 9, 4, 10, 0, i)) }));
    }
    log.record(web({ url: '/api/items?id=1 UNION SELECT', status: 200, timestamp: new Date('2026-10-04T11:00:00Z') }));
    log.flush();

    const findings = groupFindings(readAttacks(dir), readTriage(dir));
    expect(findings).toHaveLength(2);
    expect(findings[0].path).toBe('/api/items');
    expect(findings[0].outcome).toBe('answered');
    expect(findings[1].count).toBe(5);
    expect(findings[1].outcome).toBe('refused');

    const id = findings[0].id;
    expect(findFinding(findings, id.slice(0, 4))?.id).toBe(id);
    setTriage(dir, id, { status: 'fixed', pr: 'https://github.com/x/y/pull/1' });
    const after = groupFindings(readAttacks(dir), readTriage(dir));
    // Triaged findings sink below untriaged ones.
    expect(after[1].id).toBe(id);
    expect(after[1].triage).toMatchObject({ status: 'fixed', pr: 'https://github.com/x/y/pull/1' });
    expect(JSON.parse(readFileSync(join(dir, 'triage.json'), 'utf8'))[id].status).toBe('fixed');
  });

  it('marks a finding answered when any one repeat was answered', () => {
    const records = [
      toRecord(web({ status: 404 })),
      toRecord(web({ status: 200, timestamp: new Date('2026-10-04T10:05:00Z') })),
    ];
    const [f] = groupFindings(records);
    expect(f.outcome).toBe('answered');
    expect(f.statuses).toEqual({ 404: 1, 200: 1 });
    expect(f.samples[0].status).toBe(200);
  });
});

describe('brief + repro', () => {
  it('produces a shell-safe curl against the vhost that was hit', () => {
    const cmd = reproCommand(toRecord(web()));
    expect(cmd).toContain("'https://example.com/search?q=1'\\'' OR '\\''1'\\''='\\''1'");
  });

  it('includes outcome, repro, and the mark commands', () => {
    const [f] = groupFindings([toRecord(web())]);
    const md = findingBrief(f);
    expect(md).toMatch(/^# Watchdog finding [0-9a-f]{10}: sqli on example\.com GET \/search/);
    expect(md).toContain('**Outcome:** answered');
    expect(md).toContain('curl -sk');
    expect(md).toContain(`threatcrush watchdog mark ${f.id} fixed --pr <url>`);
  });
});
