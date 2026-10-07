import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ThreatEvent } from '../../types/events.js';
import { MAX_WINDOW_ENTRIES, RuleEngine, type DetectionRule } from '../rules/engine.js';

const T0 = Date.parse('2026-10-07T00:00:00Z');

const rule = (over: Partial<DetectionRule> = {}): DetectionRule => ({
  id: 'probe',
  title: 'Probe',
  description: 'probing',
  version: '1',
  category: 'web',
  severity: 'high',
  source_types: [],
  match: { field: 'message', operator: 'contains', value: 'GET' },
  threshold: 5,
  window_seconds: 60,
  cooldown_seconds: 300,
  tags: [],
  enabled: true,
  ...over,
});

const hit = (ip: string, path = '/x'): ThreatEvent => ({
  timestamp: new Date(),
  module: 'log-watcher',
  category: 'web',
  severity: 'low',
  message: `GET ${path}`,
  source_ip: ip,
  details: { path, ua: 'x'.repeat(500) },
});

describe('rule windows do not leak (dev2: ~280 MB/h of heap)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
  });
  afterEach(() => vi.useRealTimers());

  it('a window whose address never comes back is gone once its rule window has passed', () => {
    const engine = new RuleEngine(() => {});
    engine.loadRules([rule()]);
    for (let i = 0; i < 10_000; i++) engine.evaluate(hit(`10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`));
    expect(engine.windowCount()).toBe(10_000);
    // Inside the window: kept (they may still add up to a detection).
    expect(engine.cleanup(T0 + 30_000)).toBe(0);
    // Past it: every one-off window is forgotten. The old cleanup kept them all.
    expect(engine.cleanup(T0 + 61_000)).toBe(10_000);
    expect(engine.windowCount()).toBe(0);
  });

  it('still fires at the threshold, and a cooldown outlives an emptied window', () => {
    const fired: string[] = [];
    const engine = new RuleEngine((d) => fired.push(`${d.source_ip} ${d.description}`));
    engine.loadRules([rule()]);
    for (let i = 0; i < 5; i++) engine.evaluate(hit('203.0.113.9'));
    expect(fired).toEqual(['203.0.113.9 probing (5 events in 60s)']);
    // The window is empty after firing, but the cooldown is still running.
    expect(engine.cleanup(T0 + 120_000)).toBe(0);
    vi.setSystemTime(T0 + 120_000);
    for (let i = 0; i < 5; i++) engine.evaluate(hit('203.0.113.9'));
    expect(fired).toHaveLength(1); // cooling down
    expect(engine.cleanup(T0 + 400_000)).toBe(1);
  });

  it('an aggregate window keeps at most MAX_WINDOW_ENTRIES, and says so', () => {
    const fired: string[] = [];
    const engine = new RuleEngine((d) => fired.push(d.description));
    engine.loadRules([rule({ id: 'swarm', group_by: 'global', threshold: 3 * MAX_WINDOW_ENTRIES, window_seconds: 3600 })]);
    for (let i = 0; i < 3 * MAX_WINDOW_ENTRIES - 1; i++) engine.evaluate(hit(`198.51.${(i >> 8) & 255}.${i & 255}`));
    expect(fired).toEqual([]);
    engine.evaluate(hit('198.51.100.1'));
    expect(fired).toHaveLength(1);
    expect(fired[0]).toMatch(/\(3000 events in 3600s from \d+ addresses\)/);

    const small = new RuleEngine((d) => fired.push(d.description));
    small.loadRules([rule({ id: 'swarm2', group_by: 'global', threshold: 10, window_seconds: 3600, cooldown_seconds: 600 })]);
    for (let i = 0; i < 10; i++) small.evaluate(hit(`192.0.2.${i}`));
    vi.setSystemTime(T0 + 60_000); // inside the cooldown: entries pile up, capped
    for (let i = 0; i < 5 * MAX_WINDOW_ENTRIES; i++) small.evaluate(hit(`192.0.2.${i & 255}`));
    vi.setSystemTime(T0 + 700_000); // cooldown over: the next event fires with a capped count
    small.evaluate(hit('192.0.2.1'));
    expect(fired.at(-1)).toMatch(/\(1000\+ events in 3600s/);
  });
});
