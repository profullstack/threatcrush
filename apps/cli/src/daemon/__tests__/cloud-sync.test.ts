import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { join } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';
import { fakeCloud, isolateHome, settle, type FakeReply, type RecordedRequest } from './helpers/fake-cloud.js';

// Imported after isolateHome(): cli-config and paths fix ~/.threatcrush at load time.
const home = isolateHome();
const { writeCliConfig, readCliConfig, cloudFetch } = await import('../../core/cli-config.js');
const { CloudSync } = await import('../workers/cloud-sync.js');
const { CloudSpool } = await import('../workers/cloud-spool.js');
const { EventBus } = await import('../event-bus.js');

let n = 0;
const spoolPath = () => join(home, `spool-${++n}.jsonl`);

function detection(i: number, severity: ThreatEvent['severity'] = 'high'): ThreatEvent {
  return {
    timestamp: new Date('2026-09-25T12:00:00Z'),
    module: 'rule-engine',
    category: 'auth',
    severity,
    message: `[DETECTION] SSH Brute Force Detected #${i}`,
    source_ip: '203.0.113.9',
    details: { rule_id: 'ssh-brute-force', description: 'Multiple failed SSH logins', username: 'root' },
  };
}

function makeSync(bus: InstanceType<typeof EventBus>, path: string, extra: Record<string, unknown> = {}) {
  const logs: string[] = [];
  const sync = new CloudSync({
    bus,
    version: '9.9.9',
    hostname: 'box-1',
    minSeverity: 'medium',
    spoolPath: path,
    log: (line) => logs.push(line),
    ruleModules: new Set(['ssh-guard', 'log-watcher']),
    flushMs: 3_600_000,
    heartbeatMs: 3_600_000,
    baseBackoffMs: 1_000,
    ...extra,
  });
  return { sync, logs };
}

const ingestOk: FakeReply = { status: 200, body: { success: true, accepted: {}, rejected: [] } };
const detectionsIn = (reqs: RecordedRequest[]) =>
  reqs.flatMap((r) => r.body?.events ?? []).filter((e) => e.type !== 'heartbeat');

beforeEach(() => {
  writeCliConfig({ token: 'tok', refresh_token: 'r1', server_id: 'srv-1', server_org_id: 'org-1' });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('cloud sync batching', () => {
  it('sends a full batch of 100 at once, without waiting for the timer', async () => {
    const cloud = fakeCloud(() => ingestOk);
    const bus = new EventBus();
    const { sync } = makeSync(bus, spoolPath());
    sync.start();
    await settle();

    for (let i = 0; i < 100; i++) bus.publish(detection(i));
    await settle();

    const batches = cloud.to('/api/ingest').filter((r) => r.body?.events?.[0]?.type === 'detection');
    expect(batches).toHaveLength(1);
    expect(batches[0].body?.events).toHaveLength(100);
    expect(batches[0].body?.events?.[0]).toMatchObject({
      type: 'detection',
      server_id: 'srv-1',
      rule_id: 'ssh-brute-force',
      severity: 'high',
      title: 'SSH Brute Force Detected #0',
      description: 'Multiple failed SSH logins',
      source_ip: '203.0.113.9',
      username: 'root',
      detected_at: '2026-09-25T12:00:00.000Z',
    });
    expect(sync.queued).toBe(0);
    await sync.stop();
  });

  it('holds a partial batch until the flush interval, then sends it', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'setTimeout'] });
    const cloud = fakeCloud(() => ingestOk);
    const bus = new EventBus();
    const { sync } = makeSync(bus, spoolPath(), { flushMs: 10_000 });
    sync.start();
    await settle();

    for (let i = 0; i < 3; i++) bus.publish(detection(i));
    await settle();
    expect(detectionsIn(cloud.requests)).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(10_000);
    await settle();
    expect(detectionsIn(cloud.requests)).toHaveLength(3);
    await sync.stop();
  });

  it('uploads only rule detections and uncovered modules at or above min_severity', async () => {
    const cloud = fakeCloud(() => ingestOk);
    const bus = new EventBus();
    const { sync } = makeSync(bus, spoolPath());
    sync.start();

    bus.publish(detection(1, 'low'));
    // Raw evidence the ssh-brute-force rule counts: the rule's detection is the upload.
    bus.publish({ ...detection(2), module: 'ssh-guard', message: 'Failed SSH login for root', details: {} });
    // dns-monitor's proof-of-life is not a detection.
    bus.publish({ ...detection(3, 'info'), module: 'dns-monitor', details: { heartbeat: true } });
    // No rule reads dns-monitor, so its own high event is the detection.
    bus.publish({ ...detection(4), module: 'dns-monitor', message: 'DNS tunneling suspected', details: {} });
    bus.publish(detection(5, 'medium'));
    await sync.flush();

    const sent = detectionsIn(cloud.requests);
    expect(sent.map((e) => [e.rule_id, e.title])).toEqual([
      ['dns-monitor', 'DNS tunneling suspected'],
      ['ssh-brute-force', 'SSH Brute Force Detected #5'],
    ]);
    await sync.stop();
  });

  it('keeps raw_metadata under 16 KB', async () => {
    const cloud = fakeCloud(() => ingestOk);
    const bus = new EventBus();
    const { sync } = makeSync(bus, spoolPath());
    sync.start();
    const big = Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`k${i}`, 'x'.repeat(900)]));
    bus.publish({ ...detection(1), details: { rule_id: 'r', ...big } });
    await sync.flush();

    const [event] = detectionsIn(cloud.requests);
    expect(Buffer.byteLength(JSON.stringify(event.raw_metadata))).toBeLessThanOrEqual(16 * 1024);
    expect(event.raw_metadata).toMatchObject({ _truncated: true, module: 'rule-engine' });
    await sync.stop();
  });

  it('reports bans as remediation events, but not ones the dashboard asked for', async () => {
    const cloud = fakeCloud(() => ingestOk);
    const bus = new EventBus();
    const { sync } = makeSync(bus, spoolPath());
    sync.start();
    const ban = (origin?: string): ThreatEvent => ({
      timestamp: new Date('2026-09-25T12:00:00Z'),
      module: 'firewall-rules',
      category: 'system',
      severity: 'info',
      message: '[DRY-RUN] Banned 203.0.113.9 for 1m',
      source_ip: '203.0.113.9',
      details: { action: 'block', rule_id: 'ssh-brute-force', reason: 'brute force', dry_run: true, ttl_seconds: 60, origin },
    });
    bus.publish(ban());
    bus.publish(ban('cloud'));
    await sync.flush();

    expect(detectionsIn(cloud.requests)).toEqual([{
      type: 'remediation',
      server_id: 'srv-1',
      action_type: 'block',
      target_value: '203.0.113.9',
      status: 'executed',
      rule_id: 'ssh-brute-force',
      reason: 'brute force',
      dry_run: true,
      executed_at: '2026-09-25T12:00:00.000Z',
      expires_at: '2026-09-25T12:01:00.000Z',
    }]);
    await sync.stop();
  });

  it('sends a heartbeat with version and hostname on start', async () => {
    const cloud = fakeCloud(() => ingestOk);
    const { sync } = makeSync(new EventBus(), spoolPath());
    sync.start();
    await settle();
    expect(cloud.to('/api/ingest')[0].body?.events).toEqual([
      { type: 'heartbeat', server_id: 'srv-1', version: '9.9.9', hostname: 'box-1' },
    ]);
    await sync.stop();
  });

  it('does nothing while the machine is not linked', async () => {
    writeCliConfig({ token: 'tok', refresh_token: 'r1' });
    const cloud = fakeCloud(() => ingestOk);
    const bus = new EventBus();
    const { sync } = makeSync(bus, spoolPath());
    sync.start();
    bus.publish(detection(1));
    await sync.flush();
    expect(cloud.requests).toHaveLength(0);
    expect(sync.queued).toBe(0);
    await sync.stop();
  });
});

describe('cloud sync failure handling', () => {
  it('drops a batch the server refuses with 400 and moves on', async () => {
    let refuse = true;
    const cloud = fakeCloud((req) => {
      if (req.body?.events?.[0]?.type === 'heartbeat') return ingestOk;
      return refuse ? { status: 400, body: { error: 'events array is required' } } : ingestOk;
    });
    const bus = new EventBus();
    const { sync, logs } = makeSync(bus, spoolPath());
    sync.start();
    bus.publish(detection(1));
    await sync.flush();
    expect(sync.queued).toBe(0);
    expect(logs.some((l) => l.includes('400'))).toBe(true);

    refuse = false;
    bus.publish(detection(2));
    await sync.flush();
    expect(detectionsIn(cloud.requests).map((e) => e.title)).toEqual([
      'SSH Brute Force Detected #1', // the refused attempt
      'SSH Brute Force Detected #2',
    ]);
    await sync.stop();
  });

  it('spools while the dashboard is down and replays after a restart', async () => {
    const path = spoolPath();
    let down = true;
    const cloud = fakeCloud(() => (down ? 'network-down' : ingestOk));
    const bus = new EventBus();
    const first = makeSync(bus, path);
    first.sync.start();
    for (let i = 0; i < 5; i++) bus.publish(detection(i));
    await first.sync.flush();
    expect(first.sync.queued).toBe(5);
    expect(first.logs.some((l) => l.includes('unreachable'))).toBe(true);
    await first.sync.stop();

    down = false;
    cloud.requests.length = 0;
    const second = makeSync(new EventBus(), path);
    second.sync.start();
    await second.sync.flush();
    expect(detectionsIn(cloud.requests).map((e) => e.title)).toEqual(
      [0, 1, 2, 3, 4].map((i) => `SSH Brute Force Detected #${i}`),
    );
    expect(second.sync.queued).toBe(0);
    await second.sync.stop();

    // Delivered events are gone from disk too.
    const third = makeSync(new EventBus(), path);
    expect(third.sync.queued).toBe(0);
  });

  it('backs off after a 5xx instead of retrying on every flush', async () => {
    const cloud = fakeCloud((req) => (req.body?.events?.[0]?.type === 'heartbeat' ? ingestOk : { status: 503 }));
    const bus = new EventBus();
    const { sync } = makeSync(bus, spoolPath(), { baseBackoffMs: 60_000 });
    sync.start();
    await settle();
    bus.publish(detection(1));
    await sync.flush();
    await sync.flush();
    await sync.flush();
    expect(detectionsIn(cloud.requests)).toHaveLength(1);
    expect(sync.queued).toBe(1);
    await sync.stop();
  });
});

describe('spool bound', () => {
  it('drops the oldest events past the cap and keeps the rest across a restart', async () => {
    const path = spoolPath();
    const spool = new CloudSpool(path, { maxEvents: 5, maxBytes: 1024 * 1024 });
    for (let i = 0; i < 8; i++) spool.push({ i });
    expect(spool.size).toBe(5);
    expect(spool.takeDropped()).toBe(3);
    await spool.settled();

    const reopened = new CloudSpool(path, { maxEvents: 5, maxBytes: 1024 * 1024 });
    expect(reopened.peek(10, 1024 * 1024)).toEqual([3, 4, 5, 6, 7].map((i) => ({ i })));
  });

  it('bounds by bytes as well as by count', async () => {
    const spool = new CloudSpool(spoolPath(), { maxEvents: 1000, maxBytes: 250 });
    for (let i = 0; i < 10; i++) spool.push({ pad: 'x'.repeat(80), i });
    expect(spool.size).toBe(2);
    expect(spool.peek(10, 1e6)).toEqual([8, 9].map((i) => ({ pad: 'x'.repeat(80), i })));
    await spool.settled();
  });
});

describe('session refresh', () => {
  it('refreshes once for concurrent 401s, retries each request, and saves the rotated tokens', async () => {
    writeCliConfig({ token: 'old', refresh_token: 'r1', expires_at: 4_000_000_000 });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const cloud = fakeCloud(async (req) => {
      if (req.path === '/api/auth/refresh') {
        await gate; // hold the refresh open so every caller piles onto it
        return req.body?.refresh_token === 'r1'
          ? { status: 200, body: { session: { access_token: 'new', refresh_token: 'r2', expires_at: 4_000_000_100 } } }
          : { status: 401 };
      }
      return req.auth === 'Bearer new' ? { status: 200, body: { ok: true } } : { status: 401 };
    });

    const calls = Promise.all([
      cloudFetch('/api/ingest', { method: 'POST', body: '{"events":[]}' }),
      cloudFetch('/api/orgs/org-1/servers/srv-1/remediations/claim', { method: 'POST', body: '{}' }),
      cloudFetch('/api/orgs/org-1/allowlists'),
    ]);
    await settle();
    release();
    const responses = await calls;

    expect(responses.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(cloud.to('/api/auth/refresh')).toHaveLength(1);
    expect(readCliConfig()).toMatchObject({ token: 'new', refresh_token: 'r2', expires_at: 4_000_000_100 });
  });

  it('refreshes before sending when the stored token has expired', async () => {
    writeCliConfig({ token: 'old', refresh_token: 'r1', expires_at: 1 });
    const cloud = fakeCloud((req) => req.path === '/api/auth/refresh'
      ? { status: 200, body: { session: { access_token: 'new', refresh_token: 'r2', expires_at: 4_000_000_000 } } }
      : { status: req.auth === 'Bearer new' ? 200 : 401 });

    const res = await cloudFetch('/api/orgs');
    expect(res.status).toBe(200);
    expect(cloud.requests.map((r) => r.path)).toEqual(['/api/auth/refresh', '/api/orgs']);
  });

  it('returns the 401 when the refresh token is dead, and keeps events spooled', async () => {
    writeCliConfig({ token: 'old', refresh_token: 'dead', server_id: 'srv-1', server_org_id: 'org-1' });
    const cloud = fakeCloud(() => ({ status: 401 }));
    const bus = new EventBus();
    const { sync, logs } = makeSync(bus, spoolPath());
    sync.start();
    bus.publish(detection(1));
    await sync.flush();

    expect(sync.queued).toBe(1);
    expect(logs.some((l) => l.includes('threatcrush login'))).toBe(true);
    expect(readCliConfig().refresh_token).toBe('dead');
    expect(cloud.to('/api/auth/refresh').length).toBeGreaterThan(0);
    await sync.stop();
  });
});
