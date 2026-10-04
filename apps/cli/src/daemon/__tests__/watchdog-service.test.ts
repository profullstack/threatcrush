import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ThreatEvent } from '../../types/events.js';
import { startWatchdog } from '../watchdog-service.js';
import { readAttacks, setTriage } from '../../core/watchdog.js';

const attack = (status: number, second: number): ThreatEvent => ({
  timestamp: new Date(Date.UTC(2026, 9, 4, 12, 0, second)),
  module: 'log-watcher',
  category: 'web',
  severity: 'high',
  message: `Attack [SQLI]: GET /q?id=1'--${second}`,
  source_ip: '203.0.113.9',
  details: { host: 'example.com', path: '/q', method: 'GET', status, attack_type: 'sqli', crs_score: 9 },
});

describe('daemon watchdog service', () => {
  let stateDir: string;
  const lines: string[] = [];
  const log = (l: string) => { lines.push(l); };

  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), 'tc-wd-svc-'));
    lines.length = 0;
  });
  afterEach(() => { rmSync(stateDir, { recursive: true, force: true }); });

  it('logs attacks from the bus, reports counts, and flushes on stop', () => {
    const bus = new EventEmitter();
    const svc = startWatchdog({ bus, stateDir, log, flushMs: 60_000 });
    bus.emit('event', attack(200, 1));
    bus.emit('event', attack(500, 2));
    bus.emit('event', { timestamp: new Date(), module: 'x', category: 'system', severity: 'info', message: 'noise' });
    expect(svc.status()).toMatchObject({ enabled: true, logged: 2, answered: 1, errored: 1, dir: join(stateDir, 'watchdog') });

    svc.stop();
    expect(readAttacks(join(stateDir, 'watchdog'))).toHaveLength(2);
    // Stopped: the listener is gone.
    bus.emit('event', attack(200, 3));
    expect(svc.status().logged).toBe(2);
  });

  it('does nothing when [watchdog] enabled = false', () => {
    const bus = new EventEmitter();
    const svc = startWatchdog({ bus, stateDir, log, config: { enabled: false } });
    bus.emit('event', attack(200, 1));
    svc.stop();
    expect(svc.status().enabled).toBe(false);
    expect(existsSync(join(stateDir, 'watchdog'))).toBe(false);
  });

  it('honours [watchdog] dir', () => {
    const bus = new EventEmitter();
    const dir = join(stateDir, 'elsewhere');
    const svc = startWatchdog({ bus, stateDir, log, config: { dir } });
    bus.emit('event', attack(200, 1));
    svc.stop();
    expect(readAttacks(dir)).toHaveLength(1);
  });

  it('reports, rather than throws, when the directory cannot be created', () => {
    const bus = new EventEmitter();
    // A path under a regular file fails fast with ENOTDIR. (Not /proc: Node's
    // recursive mkdir spins forever there.)
    const file = join(stateDir, 'not-a-dir');
    writeFileSync(file, 'x');
    const svc = startWatchdog({ bus, stateDir, log, config: { dir: join(file, 'watchdog') } });
    expect(svc.status().enabled).toBe(false);
    expect(svc.status().error).toBeTruthy();
    expect(lines.some((l) => l.startsWith('[watchdog] cannot open'))).toBe(true);
  });

  it('shares the log with a group: setgid dir, group-writable log and verdicts', () => {
    const bus = new EventEmitter();
    const gid = process.getgid!();
    const svc = startWatchdog({ bus, stateDir, log, shareGid: gid });
    bus.emit('event', attack(200, 1));
    svc.stop();
    const dir = join(stateDir, 'watchdog');
    expect(statSync(dir).mode & 0o7777).toBe(0o2770);
    expect(statSync(join(dir, 'attacks.jsonl')).mode & 0o777).toBe(0o660);
    setTriage(dir, 'abc', { status: 'fp' });
    expect(statSync(join(dir, 'triage.json')).mode & 0o777).toBe(0o660);
  });
});
