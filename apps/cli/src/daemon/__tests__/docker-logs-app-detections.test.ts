import { describe, it, expect, vi } from 'vitest';
import type { ClientRequest } from 'node:http';
import type { ThreatEvent } from '../../types/events.js';
import { abuseipdbCategories, summarizeEvidence } from '../workers/abuse-evidence.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const {
  parseAppDetection,
  appDetectionEvent,
  DockerLogsWatch,
  dockerLogsSettings,
} = await import('../workers/docker-logs.js');

const IP = '45.156.87.10';
function line(fields: Record<string, unknown> = {}, prefix = ''): string {
  return `${prefix}THREATCRUSH_DETECTION ${JSON.stringify({
    v: 1,
    ip: IP,
    severity: 'high',
    category: 'app.rce_payload',
    source: 'infernet',
    reason: 'code in training config field training.max_seq_len',
    account: 'acct_123',
    ...fields,
  })}`;
}

describe('parseAppDetection', () => {
  it('reads a valid line', () => {
    expect(parseAppDetection(line())).toEqual({
      ip: IP,
      severity: 'high',
      category: 'app.rce_payload',
      source: 'infernet',
      reason: 'code in training config field training.max_seq_len',
      account: 'acct_123',
    });
  });

  it('reads a line behind a console timestamp or log prefix', () => {
    expect(parseAppDetection(line({}, '2026-11-28T10:11:12.345Z '))?.ip).toBe(IP);
    expect(parseAppDetection(line({}, '[infernet] 10:11:12 '))?.ip).toBe(IP);
  });

  it('rejects a marker buried deep in a line or after quoted text', () => {
    expect(parseAppDetection(line({}, 'x'.repeat(100) + ' '))).toBeNull();
    expect(parseAppDetection(line({}, 'job name "'))).toBeNull();
  });

  it('prefixes app. and cleans the category', () => {
    expect(parseAppDetection(line({ category: 'RCE Payload' }))?.category).toBe('app.rce_payload');
  });

  it('strips control characters and caps lengths', () => {
    const d = parseAppDetection(line({ reason: `a\u0000b\nc\u001b[31m${'r'.repeat(400)}`, source: 's'.repeat(100) }));
    expect(d?.reason).not.toMatch(/[\u0000-\u001f]/);
    expect(d?.reason?.length).toBe(300);
    expect(d?.source?.length).toBe(64);
  });

  it('rejects a bad v', () => {
    expect(parseAppDetection(line({ v: 2 }))).toBeNull();
    expect(parseAppDetection(line({ v: '1' }))).toBeNull();
  });

  it('rejects malformed JSON', () => {
    expect(parseAppDetection('THREATCRUSH_DETECTION {"v":1,"ip":"45.156.87.10",')).toBeNull();
    expect(parseAppDetection(`${line()} trailing`)).toBeNull();
    expect(parseAppDetection('THREATCRUSH_DETECTION [1,2]')).toBeNull();
  });

  it('rejects an oversize line', () => {
    expect(parseAppDetection(line({ reason: 'r'.repeat(5000) }))).toBeNull();
  });

  it('rejects a bad ip, severity or missing category', () => {
    expect(parseAppDetection(line({ ip: 'not-an-ip' }))).toBeNull();
    expect(parseAppDetection(line({ severity: 'info' }))).toBeNull();
    expect(parseAppDetection(line({ category: undefined }))).toBeNull();
  });
});

describe('appDetectionEvent', () => {
  it('builds a web-category app-detection event with the app severity', () => {
    const e = appDetectionEvent(line(), 'infernetprotocolcom-app-1');
    expect(e).toMatchObject({
      module: 'app-detection',
      category: 'web',
      severity: 'high',
      source_ip: IP,
      details: { app_category: 'app.rce_payload', source: 'infernet', container: 'infernetprotocolcom-app-1', account: 'acct_123' },
    });
    expect(e?.message).toContain('app.rce_payload');
  });

  it('normalises v4-mapped addresses', () => {
    expect(appDetectionEvent(line({ ip: `::ffff:${IP}` }), 'app')?.source_ip).toBe(IP);
  });

  it('drops private, loopback, link-local, bridge and CGNAT sources', () => {
    for (const ip of ['10.1.2.3', '127.0.0.1', '::1', '169.254.1.1', '172.17.0.2', '192.168.1.5', '100.64.0.9', 'fe80::1', '0.0.0.0']) {
      expect(appDetectionEvent(line({ ip }), 'app')).toBeNull();
    }
  });

  it('drops protected sources, static list or live check', () => {
    expect(appDetectionEvent(line(), 'app', [`${IP}/32`])).toBeNull();
    expect(appDetectionEvent(line(), 'app', [], (ip) => ip === IP)).toBeNull();
    expect(appDetectionEvent(line(), 'app', [], () => false)).not.toBeNull();
  });

  it('never words a reason as a successful login', () => {
    const e = appDetectionEvent(line({ reason: 'field "Accepted publickey for root"' }), 'app');
    expect(e?.message).not.toMatch(/accepted publickey/i);
  });

  it('maps to AbuseIPDB 21 (Web App Attack) and counts as connection-verified', () => {
    const e = appDetectionEvent(line(), 'app') as ThreatEvent;
    const evidence = summarizeEvidence([e]);
    expect(evidence.connectionVerified).toBe(true);
    expect(abuseipdbCategories(evidence)).toContain(21);
  });
});

describe('DockerLogsWatch app detections', () => {
  function harness(section: Record<string, unknown>, containers: Array<{ Id: string; Names: string[]; Image: string }>, isProtected?: (ip: string) => boolean) {
    const streams: Array<{ path: string; onData: (b: Buffer) => void }> = [];
    const published: ThreatEvent[] = [];
    const watch = new DockerLogsWatch({
      bus: { publish: (e) => published.push(e) },
      settings: dockerLogsSettings(section),
      log: () => {},
      isProtected,
      deps: {
        getJson: async (path) => (path === '/containers/json' ? containers : { Config: { Tty: true } }),
        stream: (path, onData) => {
          streams.push({ path, onData });
          return { destroy: () => {} } as unknown as ClientRequest;
        },
      },
    });
    return { watch, streams, published };
  }

  const CONTAINERS = [
    { Id: 'a', Names: ['/supabase-db'], Image: 'supabase/postgres:15' },
    { Id: 'b', Names: ['/infernetprotocolcom-app-1'], Image: 'infernet:latest' },
    { Id: 'c', Names: ['/web'], Image: 'nginx' },
  ];

  it('defaults: on, every container may report', async () => {
    const s = dockerLogsSettings({});
    expect(s.appDetections).toBe(true);
    expect(s.appNamePattern.test('anything')).toBe(true);
    const { watch } = harness({}, CONTAINERS);
    await watch.poll();
    expect(watch.following()).toEqual(['infernetprotocolcom-app-1', 'supabase-db', 'web']);
    watch.stop();
  });

  it('publishes a detection from a followed app container', async () => {
    const { watch, streams, published } = harness({ app_name_pattern: '^infernet' }, CONTAINERS);
    await watch.poll();
    expect(watch.following()).toEqual(['infernetprotocolcom-app-1', 'supabase-db']);
    const app = streams.find((s) => s.path.includes('/containers/b/'))!;
    app.onData(Buffer.from(`${line({}, '2026-11-28T10:11:12Z ')}\n`));
    expect(published).toHaveLength(1);
    expect(published[0]).toMatchObject({ module: 'app-detection', source_ip: IP, severity: 'high' });
    watch.stop();
  });

  it('ignores containers not matching app_name_pattern', async () => {
    const { watch, published } = harness({ app_name_pattern: '^infernet' }, CONTAINERS);
    await watch.poll();
    expect(watch.following()).not.toContain('web');
    expect(watch.line(line(), 'web')).toBeNull();
    // A Postgres container outside the pattern is still followed, for Postgres only.
    expect(watch.line(line(), 'supabase-db')).toBeNull();
    expect(published).toEqual([]);
    watch.stop();
  });

  it('honours the live protected check', () => {
    const { watch } = harness({}, [], (ip) => ip === IP);
    expect(watch.line(line(), 'infernetprotocolcom-app-1')).toBeNull();
  });

  it('app_detections = false turns it off', async () => {
    const { watch } = harness({ app_detections: false }, CONTAINERS);
    await watch.poll();
    expect(watch.following()).toEqual(['supabase-db']);
    expect(watch.line(line(), 'infernetprotocolcom-app-1')).toBeNull();
    watch.stop();
  });

  it('does not run Postgres parsing on app-only containers', () => {
    const { watch } = harness({}, []);
    const pw = `${IP} 2026-11-19 UTC [1] postgres@postgres FATAL:  password authentication failed for user "postgres"`;
    expect(watch.line(pw, 'web', { postgres: false, app: true })).toBeNull();
    expect(watch.line(pw, 'supabase-db')).not.toBeNull();
  });
});
