import { describe, expect, it } from 'vitest';
import { renderToText } from '@profullstack/hqtui';
import { renderDashboard } from '../view.js';
import { threatcrushTheme } from '../theme.js';
import { initialState, isBanned, reducer, selectedIp, type State } from '../state.js';
import type { BlocklistReply } from '../../daemon/ipc-protocol.js';

const SIZE = { width: 160, height: 44, theme: threatcrushTheme };

function screen(state: State): string {
  return renderToText(({ ui, theme }) => renderDashboard(ui, state, theme, {}), SIZE);
}

const NOW = Date.now();

function blocklist(overrides: Partial<BlocklistReply> = {}): BlocklistReply {
  return {
    entries: [
      {
        ip: '45.33.22.11',
        reason: 'Failed SSH login for root',
        blocked_at: NOW - 30_000,
        expires_at: NOW + 450_000,
        strikes: 5,
        source: 'auto',
        dry_run: false,
      },
      {
        ip: '185.220.101.44',
        reason: 'banned from dashboard',
        blocked_at: NOW - 10_000,
        expires_at: NOW + 50_000,
        strikes: 1,
        source: 'manual',
        dry_run: false,
      },
    ],
    protected: ['127.0.0.0/8', '10.0.0.0/8', '203.0.113.7'],
    enabled: true,
    dry_run: false,
    backend: 'fail2ban',
    min_severity: 'high',
    ...overrides,
  };
}

function withSources(state: State): State {
  return reducer(state, {
    type: 'top',
    top: [
      { ip: '45.33.22.11', count: 91 },
      { ip: '185.220.101.44', count: 44 },
      { ip: '103.77.88.99', count: 7 },
    ],
  });
}

describe('ban state', () => {
  it('takes the ban list and the firewall summary from the daemon', () => {
    const state = reducer(initialState(), { type: 'blocklist', reply: blocklist() });
    expect(state.bans).toHaveLength(2);
    expect(state.firewall?.backend).toBe('fail2ban');
    expect(isBanned(state, '45.33.22.11')).toBe(true);
    expect(isBanned(state, '8.8.8.8')).toBe(false);
  });

  it('offers nothing to ban while the feed has focus', () => {
    const state = withSources(initialState());
    expect(state.focus).toBe('feed');
    expect(selectedIp(state)).toBeNull();
  });

  it('selects a source once the threats panel is focused', () => {
    let state = withSources(initialState());
    state = reducer(state, { type: 'focus_next' });
    expect(state.focus).toBe('threats');
    expect(selectedIp(state)).toBe('45.33.22.11');

    state = reducer(state, { type: 'select', delta: 1 });
    expect(selectedIp(state)).toBe('185.220.101.44');
  });

  it('clamps the selection at both ends of the list', () => {
    let state = reducer(withSources(initialState()), { type: 'focus', focus: 'threats' });
    state = reducer(state, { type: 'select', delta: -5 });
    expect(selectedIp(state)).toBe('45.33.22.11');
    state = reducer(state, { type: 'select', delta: 99 });
    expect(selectedIp(state)).toBe('103.77.88.99');
  });

  it('keeps the selection on the same address when the ranking reorders', () => {
    // Top sources re-poll every two seconds. A fixed index would mean the ban
    // key hits a different address than the one that was highlighted.
    let state = reducer(withSources(initialState()), { type: 'focus', focus: 'threats' });
    state = reducer(state, { type: 'select', delta: 2 });
    expect(selectedIp(state)).toBe('103.77.88.99');

    state = reducer(state, {
      type: 'top',
      top: [
        { ip: '103.77.88.99', count: 120 },
        { ip: '45.33.22.11', count: 91 },
        { ip: '185.220.101.44', count: 44 },
      ],
    });
    expect(selectedIp(state)).toBe('103.77.88.99');
  });

  it('selects out of the ban list when that panel has focus', () => {
    let state = reducer(initialState(), { type: 'blocklist', reply: blocklist() });
    state = reducer(state, { type: 'focus', focus: 'bans' });
    expect(selectedIp(state)).toBe('45.33.22.11');
    state = reducer(state, { type: 'select', delta: 1 });
    expect(selectedIp(state)).toBe('185.220.101.44');
  });

  it('cycles focus feed → threats → bans → feed', () => {
    let state = initialState();
    const seen = [state.focus];
    for (let i = 0; i < 3; i++) {
      state = reducer(state, { type: 'focus_next' });
      seen.push(state.focus);
    }
    expect(seen).toEqual(['feed', 'threats', 'bans', 'feed']);
  });

  it('ages a notice out on the tick that passes its deadline', () => {
    let state = reducer(initialState(), {
      type: 'notice',
      text: 'banned 1.2.3.4 for 1m',
      tone: 'ok',
      now: Date.now() - 10_000,
    });
    expect(state.notice?.text).toContain('banned');
    state = reducer(state, { type: 'tick' });
    expect(state.notice).toBeNull();
  });

  it('never clears the firewall on a view reset', () => {
    // Reset wipes the screen's counters. Bans belong to the daemon, and a
    // dashboard that forgot them would disagree with the host it describes.
    let state = reducer(initialState(), { type: 'blocklist', reply: blocklist() });
    state = reducer(state, { type: 'reset' });
    expect(state.bans).toHaveLength(2);
  });
});

describe('ban rendering', () => {
  it('lists each ban with its offence number and time left', () => {
    const state = reducer(withSources(initialState()), { type: 'blocklist', reply: blocklist() });
    const out = screen(state);
    expect(out).toContain('BANNED');
    expect(out).toContain('45.33.22.11');
    expect(out).toContain('#5');
    expect(out).toContain('fail2ban');
  });

  it('says what auto-defence will do when nothing is banned yet', () => {
    const state = reducer(initialState(), {
      type: 'blocklist',
      reply: blocklist({ entries: [] }),
    });
    const out = screen(state);
    expect(out).toContain('nothing banned');
    expect(out).toMatch(/1m/);
  });

  it('calls out dry-run rather than implying the host is defended', () => {
    const state = reducer(initialState(), {
      type: 'blocklist',
      reply: blocklist({ entries: [], dry_run: true }),
    });
    expect(screen(state)).toContain('dry-run');
  });

  it('says so plainly when auto-defence is off', () => {
    const state = reducer(initialState(), {
      type: 'blocklist',
      reply: blocklist({ entries: [], enabled: false }),
    });
    expect(screen(state)).toContain('auto-defence OFF');
  });

  it('offers the ban keys in the status bar', () => {
    const out = screen(withSources(initialState()));
    expect(out).toContain('ban');
    expect(out).toContain('unban');
  });

  it('shows the operator the ban/unban hint on the focused panel', () => {
    const state = reducer(withSources(initialState()), { type: 'focus', focus: 'threats' });
    expect(screen(state)).toContain('b ban');
  });
});
