import { describe, it, expect, beforeAll } from 'vitest';
import {
  initStateDB,
  insertEvent,
  pruneEvents,
  getEventCount,
  getThreatCount,
  getTopSources,
} from '../state.js';

const DAY = 86_400_000;
const NOW = Date.parse('2026-10-06T12:00:00Z');

const ev = (ageMs: number, ip: string, severity: 'info' | 'high' = 'info') =>
  insertEvent({
    timestamp: new Date(NOW - ageMs),
    module: 'log-watcher',
    category: 'web',
    severity,
    message: 'GET /',
    source_ip: ip,
  } as any);

describe('events retention (the 85 GB state.db that starved the daemon)', () => {
  beforeAll(() => {
    initStateDB(':memory:');
    for (let i = 0; i < 30; i++) ev(20 * DAY, '10.0.0.1'); // past retention
    for (let i = 0; i < 20; i++) ev(1 * DAY, '10.0.0.2', i < 5 ? 'high' : 'info');
    for (let i = 0; i < 10; i++) ev(60_000, '10.0.0.3');
  });

  it('counts every event ever recorded without scanning the table', () => {
    expect(getEventCount()).toBe(60);
  });

  it('deletes events past the retention, oldest first, in batches', () => {
    const deleted = pruneEvents({ retentionSeconds: 14 * 86_400, now: NOW, batch: 7, maxBatches: 100 });
    expect(deleted).toBe(30);
    expect(getTopSources(10).map((s) => s.ip)).not.toContain('10.0.0.1');
    // "ever recorded" keeps counting what was pruned
    expect(getEventCount()).toBe(60);
  });

  it('caps the number of rows, dropping the oldest', () => {
    const deleted = pruneEvents({ retentionSeconds: 365 * 86_400, maxEvents: 15, now: NOW, batch: 4, maxBatches: 100 });
    expect(deleted).toBe(15);
    const top = getTopSources(10);
    expect(top.find((s) => s.ip === '10.0.0.3')?.count).toBe(10);
    expect(top.find((s) => s.ip === '10.0.0.2')?.count).toBe(5);
  });

  it('threat and recent counts look at recent events only', () => {
    expect(getThreatCount()).toBe(0); // the 5 high events were the oldest 15 dropped
    expect(getEventCount(new Date(NOW - 3_600_000))).toBe(10);
  });
});
