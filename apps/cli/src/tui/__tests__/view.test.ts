import { describe, expect, it } from 'vitest';
import { renderToText } from '@profullstack/hqtui';
import { renderDashboard } from '../view.js';
import { threatcrushTheme } from '../theme.js';
import { initialState, reducer, type State } from '../state.js';
import { demoEvent } from '../demo.js';
import type { DaemonStatusReply } from '../../daemon/ipc-protocol.js';

const SIZE = { width: 160, height: 44, theme: threatcrushTheme };

function screen(state: State, demo = false): string {
  return renderToText(({ ui, theme }) => renderDashboard(ui, state, theme, { demo }), SIZE);
}

const status: DaemonStatusReply = {
  pid: 4242,
  startedAt: '2026-08-30T08:00:00.000Z',
  uptimeSeconds: 14 * 86400 + 6 * 3600,
  version: '0.11.3',
  mode: 'user',
  paths: { config: '/c', log: '/l', state: '/s', socket: '/sock' },
  modules: [
    { name: 'network-monitor', status: 'running', events: 847 },
    { name: 'ssh-guard', status: 'running', events: 47 },
    { name: 'code-scanner', status: 'stopped', events: 0 },
  ],
  counters: { events: 3891, threats: 4, alerts: 0 },
};

function live(): State {
  let state = reducer(initialState(), { type: 'connected', label: 'daemon pid 4242', status });
  for (let i = 0; i < 8; i++) state = reducer(state, { type: 'event', event: demoEvent(i) });
  return reducer(state, {
    type: 'top',
    top: [
      { ip: '91.232.105.3', count: 47 },
      { ip: '45.33.32.156', count: 23 },
      { ip: '185.43.21.8', count: 12 },
    ],
  });
}

describe('dashboard view', () => {
  it('renders the three panels the product page advertises', () => {
    const out = screen(live());
    expect(out).toContain('MODULES');
    expect(out).toContain('LIVE EVENTS');
    expect(out).toContain('TOP THREATS');
    expect(out).toContain('THREATCRUSH');
  });

  it('tells you how to start the daemon instead of faking traffic', () => {
    const state = reducer(initialState(), { type: 'connection_lost', label: 'no daemon' });
    const out = screen(state);
    expect(out).toContain('No daemon is running');
    expect(out).toContain('threatcrush start');
    expect(out).toContain('OFFLINE');
    // The old build showed eight invented attacks here.
    expect(out).not.toContain('SQLi');
    expect(out).not.toContain('brute force');
  });

  it('does not claim the daemon is missing while still connecting', () => {
    // The first frame renders before the async connect resolves. It used to
    // flash "No daemon is running" at every startup, including successful ones.
    const out = screen(initialState());
    expect(out).toContain('Looking for threatcrushd');
    expect(out).not.toContain('No daemon is running');
    expect(out).toContain('SEARCHING');
  });

  it('labels canned traffic as demo, never as live', () => {
    let state = initialState();
    for (let i = 0; i < 5; i++) state = reducer(state, { type: 'event', event: demoEvent(i) });
    const out = screen(state, true);
    expect(out).toContain('◈ DEMO');
    // The status badge must never read live while replaying canned traffic.
    expect(out).not.toContain('● LIVE');
  });

  it('shows daemon identity and uptime when connected', () => {
    const out = screen(live());
    expect(out).toContain('LIVE');
    expect(out).toContain('4242');
    expect(out).toContain('14d 6h');
    expect(out).toContain('0.11.3');
  });

  it('renders module state and top sources', () => {
    const out = screen(live());
    expect(out).toContain('network-monitor');
    expect(out).toContain('ssh-guard');
    expect(out).toContain('91.232.105.3');
    expect(out).toContain('2/3 active');
  });

  it('names the state DB when ranking is unavailable', () => {
    // An empty Top Threats panel used to read as "all quiet". It is really
    // "the daemon could not open SQLite", which is a different problem.
    const state = reducer(live(), {
      type: 'connected',
      label: 'daemon pid 4242',
      status: { ...status, stateDb: false },
    });
    const out = screen(reducer(state, { type: 'top', top: [] }));
    expect(out).toContain('state DB unavailable');
    expect(out).not.toContain('no sources yet');
  });

  it('says "no sources yet" when the DB is fine and nothing has been seen', () => {
    const state = reducer(live(), {
      type: 'connected',
      label: 'daemon pid 4242',
      status: { ...status, stateDb: true },
    });
    const out = screen(reducer(state, { type: 'top', top: [] }));
    expect(out).toContain('no sources yet');
    expect(out).not.toContain('state DB unavailable');
  });

  it('surfaces the paused state and the held count', () => {
    let state = reducer(live(), { type: 'pause' });
    state = reducer(state, { type: 'event', event: demoEvent(1) });
    const out = screen(state);
    expect(out).toContain('PAUSED');
    expect(out).toContain('1 held');
  });

  it('survives a terminal far smaller than the layout wants', () => {
    const out = renderToText(
      ({ ui, theme }) => renderDashboard(ui, live(), theme, {}),
      { width: 60, height: 18, theme: threatcrushTheme },
    );
    expect(out.split('\n')).toHaveLength(18);
    expect(out).toContain('THREATCRUSH');
  });

  it('never draws outside the viewport', () => {
    const out = screen(live());
    const lines = out.split('\n');
    expect(lines).toHaveLength(SIZE.height);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(SIZE.width);
  });
});
