import { describe, expect, it } from 'vitest';
import {
  eventsPerSecond,
  formatCount,
  formatUptime,
  initialState,
  reducer,
  severityTotal,
  TIMELINE_SLOTS,
  type State,
} from '../state.js';
import type { EventSeverity, ThreatEvent } from '../../types/events.js';

function event(severity: EventSeverity = 'info', message = 'test'): ThreatEvent {
  return { timestamp: new Date('2026-08-30T12:00:00Z'), module: 'ssh-guard', category: 'auth', severity, message };
}

function feed(state: State, count: number, severity: EventSeverity = 'info'): State {
  let next = state;
  for (let i = 0; i < count; i++) next = reducer(next, { type: 'event', event: event(severity) });
  return next;
}

describe('tui state', () => {
  it('starts out searching rather than claiming demo mode', () => {
    const state = initialState();
    expect(state.connection).toBe('searching');
    expect(state.events).toHaveLength(0);
  });

  describe('events/sec', () => {
    it('measures a rate, not the size of the event buffer', () => {
      // The blessed dashboard pushed `events.length` into the timeline, so the
      // graph climbed to the 300-event cap and then flatlined forever.
      let state = feed(initialState(), 5);
      state = reducer(state, { type: 'tick' });
      expect(state.timeline.at(-1)).toBe(5);

      // A second with no traffic must read zero, not "still 5 buffered".
      state = reducer(state, { type: 'tick' });
      expect(state.timeline.at(-1)).toBe(0);
    });

    it('averages over the trailing window', () => {
      let state = initialState();
      state = feed(state, 10);
      state = reducer(state, { type: 'tick' });
      state = feed(state, 20);
      state = reducer(state, { type: 'tick' });
      // 30 events across a 10s window.
      expect(eventsPerSecond(state, 10)).toBeCloseTo(3);
    });

    it('keeps the timeline at a fixed width', () => {
      let state = initialState();
      for (let i = 0; i < TIMELINE_SLOTS * 2; i++) state = reducer(state, { type: 'tick' });
      expect(state.timeline).toHaveLength(TIMELINE_SLOTS);
    });
  });

  describe('pause', () => {
    it('parks events instead of dropping them', () => {
      let state = reducer(initialState(), { type: 'pause' });
      expect(state.paused).toBe(true);

      state = feed(state, 3);
      expect(state.events).toHaveLength(0);
      expect(state.parked).toHaveLength(3);

      state = reducer(state, { type: 'pause' });
      expect(state.paused).toBe(false);
      expect(state.events).toHaveLength(3);
      expect(state.parked).toHaveLength(0);
    });

    it('counts parked events toward severity once replayed', () => {
      let state = reducer(initialState(), { type: 'pause' });
      state = feed(state, 2, 'critical');
      expect(severityTotal(state)).toBe(0);
      state = reducer(state, { type: 'pause' });
      expect(state.severity.critical).toBe(2);
    });
  });

  describe('counters', () => {
    it('takes totals from the daemon without local double counting', () => {
      // Previously a push incremented the counter locally and the 2s poll
      // overwrote it, so the header flickered between two different numbers.
      let state = feed(initialState(), 5);
      state = reducer(state, { type: 'counters', counters: { events: 900, threats: 12 } });
      expect(state.counters.events).toBe(900);

      state = feed(state, 5);
      expect(state.counters.events).toBe(900);
    });
  });

  describe('scrollback', () => {
    it('holds position when new events arrive', () => {
      let state = feed(initialState(), 20);
      state = reducer(state, { type: 'scroll', delta: 5 });
      expect(state.scrollBack).toBe(5);

      state = feed(state, 1);
      // The reader stays on the same line rather than being yanked to the tail.
      expect(state.scrollBack).toBe(6);
    });

    it('follows the tail again on scroll_end', () => {
      let state = feed(initialState(), 20);
      state = reducer(state, { type: 'scroll', delta: 5 });
      state = reducer(state, { type: 'scroll_end' });
      expect(state.scrollBack).toBe(0);

      state = feed(state, 1);
      expect(state.scrollBack).toBe(0);
    });

    it('cannot scroll past either end', () => {
      let state = feed(initialState(), 3);
      state = reducer(state, { type: 'scroll', delta: 99 });
      expect(state.scrollBack).toBe(2);
      state = reducer(state, { type: 'scroll', delta: -99 });
      expect(state.scrollBack).toBe(0);
    });
  });

  describe('connection', () => {
    it('reports loss without inventing data', () => {
      const state = reducer(initialState(), { type: 'connection_lost', label: 'no daemon' });
      expect(state.connection).toBe('lost');
      expect(state.daemon).toBeNull();
      expect(state.events).toHaveLength(0);
    });
  });

  describe('formatting', () => {
    it('abbreviates large counts', () => {
      expect(formatCount(0)).toBe('0');
      expect(formatCount(999)).toBe('999');
      expect(formatCount(1500)).toBe('1.5k');
      expect(formatCount(45_000)).toBe('45k');
      expect(formatCount(2_400_000)).toBe('2.4M');
    });

    it('formats uptime at the right granularity', () => {
      expect(formatUptime(45)).toBe('45s');
      expect(formatUptime(90)).toBe('1m 30s');
      expect(formatUptime(3700)).toBe('1h 1m');
      expect(formatUptime(14 * 86400 + 6 * 3600)).toBe('14d 6h');
      expect(formatUptime(-1)).toBe('—');
    });
  });
});
