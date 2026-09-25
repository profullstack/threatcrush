import { describe, expect, it } from 'vitest';
import { renderToText } from '@profullstack/hqtui';
import { renderDashboard } from '../view.js';
import { threatcrushTheme } from '../theme.js';
import { initialState, reducer, visibleEvents, type State } from '../state.js';
import type { ThreatEvent } from '../../types/events.js';

const SIZE = { width: 160, height: 44, theme: threatcrushTheme };
const screen = (state: State) =>
  renderToText(({ ui, theme }) => renderDashboard(ui, state, theme, {}), SIZE);

function event(module: string, message: string): ThreatEvent {
  return {
    timestamp: new Date('2026-09-25T13:00:00Z'),
    module,
    category: 'system',
    severity: 'info',
    message,
  };
}

/**
 * One module can drown out every other. dev1's resolver logs every query it
 * answers — 6.6 a second — and all of it arrived through `user-journal`, which
 * has no idea the lines are DNS. There was no way to look past it.
 */
function busyFeed(): State {
  let state = reducer(initialState(), {
    type: 'modules',
    modules: [
      { name: 'user-journal', status: 'running', events: 4231 },
      { name: 'dns-monitor', status: 'running', events: 12 },
      { name: 'ssh-guard', status: 'running', events: 8 },
    ],
  });
  for (let i = 0; i < 20; i++) {
    state = reducer(state, { type: 'event', event: event('user-journal', `[dns] query ${i}`) });
  }
  state = reducer(state, { type: 'event', event: event('ssh-guard', 'Failed SSH login for root') });
  return state;
}

describe('filtering the feed by module', () => {
  it('shows everything when no filter is set', () => {
    const state = busyFeed();
    expect(visibleEvents(state)).toHaveLength(21);
  });

  it('pins the feed to the selected module', () => {
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'select', delta: 2 }); // ssh-guard
    state = reducer(state, { type: 'toggle_module_filter' });

    expect(state.moduleFilter).toBe('ssh-guard');
    expect(visibleEvents(state)).toHaveLength(1);
    expect(visibleEvents(state)[0].message).toContain('Failed SSH login');
  });

  it('releases the feed when the same module is chosen again', () => {
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'toggle_module_filter' });
    expect(state.moduleFilter).toBe('user-journal');
    state = reducer(state, { type: 'toggle_module_filter' });
    expect(state.moduleFilter).toBeNull();
  });

  it('drops any scrollback when the filter changes', () => {
    // What "20 rows back" means is different once the list changes underneath.
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'scroll', delta: 5 });
    state = reducer(state, { type: 'toggle_module_filter' });
    expect(state.scrollBack).toBe(0);
  });

  it('clears on demand', () => {
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'toggle_module_filter' });
    state = reducer(state, { type: 'clear_module_filter' });
    expect(state.moduleFilter).toBeNull();
    expect(visibleEvents(state)).toHaveLength(21);
  });

  it('does nothing when there are no modules to select', () => {
    const state = reducer(initialState(), { type: 'toggle_module_filter' });
    expect(state.moduleFilter).toBeNull();
  });

  it('survives a view reset, because it is a view preference', () => {
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'toggle_module_filter' });
    state = reducer(state, { type: 'reset' });
    expect(state.moduleFilter).toBe('user-journal');
  });
});

describe('the filter is visible on screen', () => {
  it('names the module in the feed title and counts what it hid', () => {
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'select', delta: 2 });
    state = reducer(state, { type: 'toggle_module_filter' });

    const out = screen(state);
    expect(out).toContain('LIVE EVENTS');
    expect(out).toContain('ssh-guard');
    expect(out).toContain('1/21');
  });

  it('marks the pinned module in the MODULES panel', () => {
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'toggle_module_filter' });
    expect(screen(state)).toContain('▶');
  });

  it('offers the filter key while the modules panel has focus', () => {
    const state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    expect(screen(state)).toContain('filter');
  });

  it('says so when the chosen module has produced nothing', () => {
    let state = reducer(busyFeed(), { type: 'focus', focus: 'modules' });
    state = reducer(state, { type: 'select', delta: 1 }); // dns-monitor, no events
    state = reducer(state, { type: 'toggle_module_filter' });
    expect(screen(state)).toContain('No events from dns-monitor yet');
  });
});
