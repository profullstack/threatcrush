import { describe, expect, it } from 'vitest';
import { renderToScreen, renderToText } from '@profullstack/hqtui';
import { renderDashboard } from '../view.js';
import { threatcrushTheme } from '../theme.js';
import { ERROR_NOTICE_MS, NOTICE_MS, initialState, reducer } from '../state.js';

const SIZE = { width: 160, height: 44, theme: threatcrushTheme };
const NOW = 1_700_000_000_000;

describe('error messages can be copied', () => {
  it('an error stays 30s (an ok notice 6s) and is remembered for `y`', () => {
    const err = reducer(initialState(), { type: 'notice', text: 'ban failed: threatcrushd did not answer', tone: 'error', now: NOW });
    expect(err.notice?.until).toBe(NOW + ERROR_NOTICE_MS);
    expect(err.lastError).toBe('ban failed: threatcrushd did not answer');
    const ok = reducer(err, { type: 'notice', text: 'banned 1.2.3.4', tone: 'ok', now: NOW });
    expect(ok.notice?.until).toBe(NOW + NOTICE_MS);
    expect(ok.lastError).toBe('ban failed: threatcrushd did not answer');
  });

  it('a lost daemon is an error to copy; demo mode is not', () => {
    const lost = reducer(initialState(), { type: 'connection_lost', label: 'threatcrushd socket not found at /var/run/x.sock' });
    expect(lost.lastError).toBe('threatcrushd socket not found at /var/run/x.sock');
    const demo = reducer(initialState(), { type: 'connection_lost', label: 'demo mode — canned events, no daemon' });
    expect(demo.lastError).toBeNull();
  });

  it('the status bar marks the error as copyable and offers y', () => {
    const state = reducer(initialState(), { type: 'notice', text: 'ban failed: boom', tone: 'error', now: Date.now() });
    const text = renderToText(({ ui, theme }) => renderDashboard(ui, state, theme, { onCopy: () => {} }), SIZE);
    expect(text).toContain('ban failed: boom  ⧉');
    expect(text).toContain('copy error');
  });

  it('clicking the error copies its text', () => {
    const state = reducer(initialState(), { type: 'notice', text: 'ban failed: boom', tone: 'error', now: Date.now() });
    const copied: string[] = [];
    const view = ({ ui, theme }: any) => renderDashboard(ui, state, theme, { onCopy: (t) => copied.push(t) });
    const screen = renderToScreen(view, SIZE);
    const lines = renderToText(view, SIZE).split('\n');
    const y = lines.findIndex((l) => l.includes('ban failed: boom'));
    const x = lines[y].indexOf('ban failed: boom');
    screen.click(x + 2, y);
    expect(copied).toEqual(['ban failed: boom']);
  });
});
