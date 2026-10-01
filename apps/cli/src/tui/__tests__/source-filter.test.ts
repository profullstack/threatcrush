import { describe, expect, it } from 'vitest';
import { initialState, reducer, visibleEvents, type State } from '../state.js';
import type { ThreatEvent } from '../../types/events.js';

function ev(source_ip: string, message = 'Attack [RCE]: GET /x'): ThreatEvent {
  return { timestamp: new Date(), module: 'log-watcher', category: 'web', severity: 'high', message, source_ip };
}

/** A state carrying a few events and a TOP THREATS list, nothing filtered. */
function seeded(): State {
  let s = initialState();
  for (const e of [ev('1.1.1.1'), ev('2.2.2.2'), ev('1.1.1.1'), ev('3.3.3.3')]) {
    s = reducer(s, { type: 'event', event: e });
  }
  s = reducer(s, { type: 'top', top: [{ ip: '1.1.1.1', count: 2 }, { ip: '2.2.2.2', count: 1 }] });
  return reducer(s, { type: 'focus', focus: 'threats' });
}

describe('source filter', () => {
  it('shows only the selected IP, and clears on a second toggle', () => {
    let s = seeded();
    expect(visibleEvents(s)).toHaveLength(4);

    // Select the first source (1.1.1.1) and filter to it.
    s = reducer(s, { type: 'select_at', index: 0 });
    s = reducer(s, { type: 'toggle_source_filter' });
    expect(s.sourceFilter).toBe('1.1.1.1');
    expect(visibleEvents(s).map((e) => e.source_ip)).toEqual(['1.1.1.1', '1.1.1.1']);

    // Toggling the same source again clears the filter.
    s = reducer(s, { type: 'toggle_source_filter' });
    expect(s.sourceFilter).toBeNull();
    expect(visibleEvents(s)).toHaveLength(4);
  });

  it('switches to a different IP rather than clearing', () => {
    let s = seeded();
    s = reducer(s, { type: 'select_at', index: 0 });
    s = reducer(s, { type: 'toggle_source_filter' });
    expect(s.sourceFilter).toBe('1.1.1.1');
    // Point at a different row and toggle: it moves the filter, not off.
    s = reducer(s, { type: 'select_at', index: 1 });
    s = reducer(s, { type: 'toggle_source_filter' });
    expect(s.sourceFilter).toBe('2.2.2.2');
    expect(visibleEvents(s).map((e) => e.source_ip)).toEqual(['2.2.2.2']);
  });

  it('clear_source_filter and reset behave', () => {
    let s = seeded();
    s = reducer(s, { type: 'select_at', index: 0 });
    s = reducer(s, { type: 'toggle_source_filter' });
    s = reducer(s, { type: 'clear_source_filter' });
    expect(s.sourceFilter).toBeNull();

    // A filter survives a view reset (reset clears the feed, not the lens).
    s = reducer(s, { type: 'select_at', index: 0 });
    s = reducer(s, { type: 'toggle_source_filter' });
    s = reducer(s, { type: 'reset' });
    expect(s.sourceFilter).toBe('1.1.1.1');
  });
});
