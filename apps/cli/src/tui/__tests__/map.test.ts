import { writeFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { renderToText } from '@profullstack/hqtui';
import { demoMapData } from '@threatcrush/attack-map';
import { renderDashboard } from '../view.js';
import { threatcrushTheme } from '../theme.js';
import { initialState, reducer, type State } from '../state.js';
import { GeoResolver, MapImageOverlay, isPublicAddress, localMapData, sourceAddresses } from '../map.js';
import type { ThreatEvent } from '../../types/events.js';

const SIZE = { width: 160, height: 44, theme: threatcrushTheme };

function event(ip: string, severity: ThreatEvent['severity'], at: number): ThreatEvent {
  return {
    timestamp: new Date(at),
    module: 'ssh-guard',
    category: 'auth',
    severity,
    message: `failed password from ${ip}`,
    source_ip: ip,
  } as ThreatEvent;
}

function geoFetch(): typeof fetch {
  return vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    if (!init?.method) {
      return new Response(JSON.stringify({ geo: { lat: 42.88, lon: -78.87, city: 'Buffalo', countryCode: 'US' } }));
    }
    const { ips } = JSON.parse(String(init.body)) as { ips: string[] };
    const results: Record<string, unknown> = {};
    for (const ip of ips) if (ip.startsWith('45.')) results[ip] = { lat: 52.37, lon: 4.9, city: 'Amsterdam', country: 'Netherlands', countryCode: 'NL' };
    return new Response(JSON.stringify({ results }));
  }) as unknown as typeof fetch;
}

describe('isPublicAddress', () => {
  it('never sends private or loopback addresses to be placed', () => {
    expect(isPublicAddress('10.1.2.3')).toBe(false);
    expect(isPublicAddress('172.17.0.1')).toBe(false);
    expect(isPublicAddress('127.0.0.1')).toBe(false);
    expect(isPublicAddress('fe80::1')).toBe(false);
    expect(isPublicAddress('45.155.205.233')).toBe(true);
  });
});

describe('GeoResolver + localMapData', () => {
  it('places feed addresses in one batch and this server by its own address', async () => {
    const fetchImpl = geoFetch();
    const geo = new GeoResolver(() => {}, fetchImpl, 'https://example.test');
    const now = Date.now();
    let state: State = initialState(now);
    state = reducer(state, { type: 'event', event: event('45.155.205.233', 'low', now - 5000) });
    state = reducer(state, { type: 'event', event: event('45.155.205.233', 'critical', now - 1000) });
    state = reducer(state, { type: 'event', event: event('10.0.0.9', 'high', now) });
    state = reducer(state, { type: 'event', event: event('203.0.113.50', 'high', now) });

    vi.useFakeTimers();
    geo.want(sourceAddresses(state));
    await vi.advanceTimersByTimeAsync(1600);
    vi.useRealTimers();
    await new Promise((r) => setTimeout(r, 0));

    // One GET for self, one POST batch with only the public addresses.
    const calls = (fetchImpl as unknown as { mock: { calls: Array<[string, RequestInit | undefined]> } }).mock.calls;
    const posts = calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0][1]!.body)).ips.sort()).toEqual(['203.0.113.50', '45.155.205.233']);

    const data = localMapData(state, geo, 'dev2', now);
    expect(data.servers).toEqual([expect.objectContaining({ id: 'self', name: 'dev2', city: 'Buffalo' })]);
    expect(data.origins).toHaveLength(1);
    expect(data.origins[0]).toMatchObject({ ip: '45.155.205.233', count: 2, severity: 'critical', countryCode: 'NL' });
  });
});

describe('map view', () => {
  it('renders the braille map with the server, the countries and the latest sources', () => {
    const geo = new GeoResolver(() => {}, geoFetch());
    const state: State = { ...initialState(), view: 'map' };
    const now = Date.parse('2026-10-17T12:00:00Z');
    const text = renderToText(
      ({ ui, theme }) => renderDashboard(ui, state, theme, { demo: true, map: { data: demoMapData(now), geo, now } }),
      SIZE,
    );
    if (process.env.ATTACK_MAP_DUMP) writeFileSync(`${process.env.ATTACK_MAP_DUMP}/tui-map.txt`, text);
    expect(text).toContain('ATTACK MAP');
    expect(text).toContain('demo-server');
    expect(text).toContain('TOP COUNTRIES');
    expect(text).toContain('45.155.205.233');
    expect(text).toContain('m dashboard');
    expect(/[⠁-⣿]/.test(text)).toBe(true);
    // Every row is exactly the screen width: nothing spills past the side panel.
    for (const line of text.split('\n')) expect([...line].length).toBeLessThanOrEqual(SIZE.width);
  });

  it('m toggles between the panels and the map, and reset keeps the view', () => {
    let state = initialState();
    state = reducer(state, { type: 'toggle_view' });
    expect(state.view).toBe('map');
    state = reducer(state, { type: 'reset' });
    expect(state.view).toBe('map');
    state = reducer(state, { type: 'toggle_view' });
    expect(state.view).toBe('dashboard');
  });
});

describe('MapImageOverlay', () => {
  const data = demoMapData(Date.parse('2026-10-17T12:00:00Z'));

  it('sends an iTerm2 inline image sized to the panel, in hqterm', () => {
    const out: string[] = [];
    const overlay = new MapImageOverlay((s) => out.push(s), { HQTUI_IMAGES: 'iterm', TERM_PROGRAM: 'hqterm' });
    expect(overlay.mode).toBe('iterm');
    overlay.place({ col: 2, row: 4, cols: 120, rows: 30 });
    overlay.paint(data, false, 1000);
    expect(out).toHaveLength(1);
    expect(out[0]).toContain('\x1b[5;3H');
    expect(out[0]).toMatch(/\x1b\]1337;File=inline=1;width=120;height=30;/);
    // Unchanged data within a second is not re-sent; a repaint is.
    overlay.paint(data, false, 1500);
    expect(out).toHaveLength(1);
    overlay.paint(data, true, 1600);
    expect(out).toHaveLength(2);
  });

  it('uses the Kitty protocol in Kitty, and is off when asked', () => {
    const out: string[] = [];
    const kitty = new MapImageOverlay((s) => out.push(s), { HQTUI_IMAGES: '1' });
    expect(kitty.mode).toBe('kitty');
    kitty.place({ col: 0, row: 0, cols: 80, rows: 20 });
    kitty.paint(data, true, 0);
    expect(out.join('')).toMatch(/\x1b_Ga=T,f=100,i=\d+,p=1,c=80,r=20/);
    kitty.hide();
    expect(out.at(-1)).toMatch(/\x1b_Ga=d/);

    const off = new MapImageOverlay(() => {}, { HQTUI_IMAGES: 'iterm', THREATCRUSH_MAP_IMAGES: '0' });
    expect(off.enabled).toBe(false);
  });
});
