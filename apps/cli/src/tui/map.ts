import { isIP } from 'node:net';
import { Attr, hex, imageSupport, passthrough, type Container, type Theme } from '@profullstack/hqtui';
import {
  type AttackMapData,
  type AttackOrigin,
  type ServerPin,
  MAP_ASPECT,
  MAP_COLORS,
  maxSeverity,
  topCountries,
  severityColor,
} from '@threatcrush/attack-map';
import { renderCells } from '@threatcrush/attack-map/braille';
import { renderPng } from '@threatcrush/attack-map/node';
import { apiUrl } from '../core/cli-config.js';
import type { EventSeverity } from '../types/events.js';
import type { State } from './state.js';

/**
 * The attack map in the terminal: where the addresses in the live feed are,
 * with arcs to this server. The daemon knows addresses but not places, so
 * they are placed by threatcrush.com/api/geo, in batches, each address once.
 *
 * Two renderers. Everywhere: truecolor braille. In terminals that draw pixels
 * (hqterm, iTerm2, WezTerm via iTerm2 inline images; Kitty, Ghostty via the
 * Kitty protocol) the same map is drawn as an HD image over the panel.
 */

export interface GeoPoint {
  lat: number;
  lon: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

const PRIVATE_V4 = [/^10\./, /^127\./, /^0\./, /^169\.254\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./];

export function isPublicAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) return !PRIVATE_V4.some((r) => r.test(ip)) && Number(ip.split('.')[0]) < 224;
  if (v === 6) return !/^(::1?$|f[cd]|fe[89ab]|ff)/i.test(ip);
  return false;
}

/**
 * Places addresses on the globe through threatcrush.com/api/geo. Unknown
 * addresses queue up and go in one batch every couple of seconds; answers,
 * misses included, are remembered for the session so nothing is asked twice.
 */
export class GeoResolver {
  private readonly known = new Map<string, GeoPoint | null>();
  private readonly queue = new Set<string>();
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private selfAsked = false;
  /** Where this machine is, from the address threatcrush.com sees it come from. */
  self: GeoPoint | null = null;
  /** Set when the lookup service cannot be reached, for the panel to say so. */
  error: string | null = null;

  constructor(
    private readonly onUpdate: () => void,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly base: string = apiUrl(),
  ) {}

  get(ip: string): GeoPoint | null | undefined {
    return this.known.get(ip);
  }

  want(ips: Iterable<string>): void {
    if (!this.selfAsked) {
      this.selfAsked = true;
      void this.lookupSelf();
    }
    let added = false;
    for (const ip of ips) {
      if (this.known.has(ip) || this.queue.has(ip)) continue;
      if (!isPublicAddress(ip)) {
        this.known.set(ip, null);
        continue;
      }
      this.queue.add(ip);
      added = true;
    }
    if (added && !this.timer) {
      this.timer = setTimeout(() => {
        this.timer = null;
        void this.flush();
      }, 1500);
      this.timer.unref?.();
    }
  }

  private async lookupSelf(): Promise<void> {
    try {
      const res = await this.fetchImpl(`${this.base}/api/geo`, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { geo: GeoPoint | null };
      this.self = body.geo;
      this.onUpdate();
    } catch (err) {
      this.error = `geo lookup unavailable (${(err as Error).message})`;
      this.onUpdate();
    }
  }

  private async flush(): Promise<void> {
    if (this.inFlight || this.queue.size === 0) return;
    this.inFlight = true;
    const batch = [...this.queue].slice(0, 200);
    for (const ip of batch) this.queue.delete(ip);
    try {
      const res = await this.fetchImpl(`${this.base}/api/geo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips: batch }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { results: Record<string, GeoPoint> };
      for (const ip of batch) this.known.set(ip, body.results?.[ip] ?? null);
      this.error = null;
    } catch (err) {
      // Put them back for the next try; a dead network must not mark them as misses.
      for (const ip of batch) this.queue.add(ip);
      this.error = `geo lookup unavailable (${(err as Error).message})`;
    } finally {
      this.inFlight = false;
      this.onUpdate();
      if (this.queue.size > 0 && !this.timer) {
        this.timer = setTimeout(() => {
          this.timer = null;
          void this.flush();
        }, this.error ? 15_000 : 1500);
        this.timer.unref?.();
      }
    }
  }

  stop(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
}

const SEV: Record<EventSeverity, AttackOrigin['severity']> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
};

/**
 * The map's data from what the dashboard already holds: one origin per source
 * address in the feed, counted with the daemon's own top-sources tally.
 */
export function localMapData(state: State, geo: GeoResolver, hostname: string, now = Date.now()): AttackMapData {
  const by = new Map<string, AttackOrigin>();
  for (const e of state.events) {
    const ip = e.source_ip;
    if (!ip) continue;
    const at = new Date(e.timestamp).toISOString();
    const prev = by.get(ip);
    if (!prev) {
      const g = geo.get(ip);
      if (!g) continue;
      by.set(ip, { ip, ...g, count: 1, severity: SEV[e.severity] ?? 'info', lastSeen: at, serverId: 'self', category: e.category });
    } else {
      prev.count++;
      prev.severity = maxSeverity(prev.severity, SEV[e.severity] ?? 'info');
      if (at > prev.lastSeen) {
        prev.lastSeen = at;
        prev.category = e.category;
      }
    }
  }
  for (const t of state.topSources) {
    const o = by.get(t.ip);
    if (o) o.count = Math.max(o.count, t.count);
  }
  const servers: ServerPin[] = geo.self
    ? [{ id: 'self', name: hostname, ...geo.self, online: state.connection === 'live' }]
    : [];
  return { servers, origins: [...by.values()], windowMinutes: 0, generatedAt: new Date(now).toISOString() };
}

/** Every public source address in the feed, for the resolver. */
export function sourceAddresses(state: State): Set<string> {
  const out = new Set<string>();
  for (const e of state.events) if (e.source_ip) out.add(e.source_ip);
  for (const t of state.topSources) out.add(t.ip);
  return out;
}

function ago(iso: string, now: number): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h`;
}

// ----------------------------------------------------------- HD image overlay

/** Where the map image goes on screen, in absolute cells. */
export interface MapRect {
  col: number;
  row: number;
  cols: number;
  rows: number;
}

const KITTY_ID = 7461;

/**
 * Draws the map as a PNG over the map panel after each frame, in terminals
 * that can. The panel's cells are left blank so the diff renderer never
 * writes over the picture; the image is re-sent when the panel moves, when the
 * data changes, and about once a second to move the comets.
 */
export class MapImageOverlay {
  readonly mode: 'kitty' | 'iterm' | 'none';
  private rect: MapRect | null = null;
  private lastSent = 0;
  private lastKey = '';
  private shown = false;

  constructor(
    private readonly write: (s: string) => void,
    env: NodeJS.ProcessEnv = process.env,
  ) {
    const off = env.THREATCRUSH_MAP_IMAGES === '0';
    this.mode = off ? 'none' : imageSupport(env);
  }

  get enabled(): boolean {
    return this.mode !== 'none';
  }

  /** Called from the draw callback with where the map landed this frame. */
  place(rect: MapRect | null): void {
    this.rect = rect;
  }

  /** Called after each frame. */
  paint(data: AttackMapData | null, repainted: boolean, now = Date.now()): void {
    if (!this.enabled) return;
    const rect = this.rect;
    if (!rect || !data || rect.cols < 8 || rect.rows < 4) {
      this.hide();
      return;
    }
    const key = `${rect.col},${rect.row},${rect.cols},${rect.rows}:${data.servers.length}:${data.origins.length}:${data.origins.reduce((n, o) => n + o.count, 0)}`;
    if (!repainted && key === this.lastKey && now - this.lastSent < 1000) return;
    this.lastKey = key;
    this.lastSent = now;
    // Cells are about 1:2; render at a fixed pixel density, capped for bandwidth.
    const scale = Math.min(10, 1600 / rect.cols);
    const png = renderPng(data, Math.round(rect.cols * scale), Math.round(rect.rows * scale * 2), { now });
    const b64 = png.toString('base64');
    const at = `\x1b7\x1b[${rect.row + 1};${rect.col + 1}H`;
    if (this.mode === 'iterm') {
      this.write(
        passthrough(
          `${at}\x1b]1337;File=inline=1;width=${rect.cols};height=${rect.rows};preserveAspectRatio=0;size=${png.length}:${b64}\x07\x1b8`,
        ),
      );
    } else {
      // Kitty: replace image KITTY_ID's single placement, chunked to 4 KiB.
      let seq = at;
      for (let i = 0; i < b64.length; i += 4096) {
        const chunk = b64.slice(i, i + 4096);
        const more = i + 4096 < b64.length ? 1 : 0;
        seq +=
          i === 0
            ? `\x1b_Ga=T,f=100,i=${KITTY_ID},p=1,c=${rect.cols},r=${rect.rows},C=1,q=2,z=-1,m=${more};${chunk}\x1b\\`
            : `\x1b_Gm=${more};${chunk}\x1b\\`;
      }
      this.write(passthrough(`${seq}\x1b8`));
    }
    this.shown = true;
  }

  /** Take the picture down (leaving the map view, quitting). */
  hide(): void {
    if (!this.shown) return;
    this.shown = false;
    this.lastKey = '';
    if (this.mode === 'kitty') this.write(passthrough(`\x1b_Ga=d,d=I,i=${KITTY_ID},q=2\x1b\\`));
    // iTerm2 images live in the cells; the full repaint the caller does next clears them.
  }
}

// ------------------------------------------------------------------- view

export interface MapViewOptions {
  data: AttackMapData;
  geo: GeoResolver;
  overlay?: MapImageOverlay;
  now?: number;
  demo?: boolean;
}

/** The map view's body: the map, and a side panel of countries and the latest sources. */
export function mapBody(ui: Container, state: State, theme: Theme, opts: MapViewOptions): void {
  const now = opts.now ?? Date.now();
  const { data, geo, overlay } = opts;
  const total = data.origins.reduce((n, o) => n + o.count, 0);
  const countries = topCountries(data.origins, 8);
  const unplaced = [...sourceAddresses(state)].filter((ip) => geo.get(ip) === undefined && isPublicAddress(ip)).length;

  ui.row({ size: 'fill', gap: 0 }, (row) => {
    row.panel(
      {
        size: 'fill',
        title: 'ATTACK MAP',
        subtitle: `${data.origins.length} sources · ${total} events${overlay?.enabled ? ' · HD' : ''}`,
      },
      (panel) => {
        panel.draw((surface) => {
          const W = surface.width;
          const H = surface.height;
          // Keep the world's proportions: cells are about twice as tall as wide.
          let cols = W;
          let rows = Math.round(cols / MAP_ASPECT / 2);
          if (rows > H) {
            rows = H;
            cols = Math.min(W, Math.round(rows * 2 * MAP_ASPECT));
          }
          const x0 = Math.floor((W - cols) / 2);
          const y0 = Math.floor((H - rows) / 2);
          if (overlay?.enabled) {
            // Blank cells under the picture; the overlay paints after the frame.
            surface.fillRect(x0, y0, cols, rows, { bg: hex(MAP_COLORS.ocean) }, 0x20);
            overlay.place({ col: surface.rect.x + x0, row: surface.rect.y + y0, cols, rows });
          } else {
            overlay?.place(null);
            const cells = renderCells(data, cols, rows, { now });
            for (let y = 0; y < rows; y++) {
              for (let x = 0; x < cols; x++) {
                const c = cells[y][x];
                if (c.ch !== ' ') surface.char(x0 + x, y0 + y, c.ch, { fg: hex(c.fg), attrs: c.bold ? Attr.Bold : Attr.None });
              }
            }
          }
          const note = !data.servers.length
            ? geo.error ?? 'locating this server…'
            : data.origins.length === 0
              ? unplaced > 0
                ? `placing ${unplaced} sources…`
                : 'all quiet: no attacker addresses in the feed yet'
              : '';
          if (note) surface.text(Math.max(0, Math.floor((W - note.length) / 2)), H - 1, note, { fg: theme.muted });
        });
      },
    );

    row.column({ size: 34 }, (side) => {
      side.panel({ title: 'TOP COUNTRIES', size: Math.min(12, countries.length + 2) || 3 }, (p) => {
        if (countries.length === 0) p.text('nothing placed yet', { fg: theme.muted });
        const max = countries[0]?.count || 1;
        for (const c of countries) {
          const bar = '█'.repeat(Math.max(1, Math.round((c.count / max) * 10)));
          p.row({ size: 1 }, (r) => {
            r.text(`${c.code ?? '··'} ${c.country}`, { size: 'fill', fg: theme.foreground });
            r.text(` ${bar}`, { size: 11, fg: hex(MAP_COLORS.high) });
            r.text(String(c.count), { size: 6, align: 'right', fg: theme.muted });
          });
        }
      });
      side.panel({ title: 'LATEST', size: 'fill' }, (p) => {
        const latest = [...data.origins].sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).slice(0, 30);
        for (const o of latest) {
          p.row({ size: 1 }, (r) => {
            r.text('●', { size: 2, fg: hex(severityColor(o.severity)) });
            r.text(o.ip, { size: 'fill', fg: theme.foreground });
            r.text(ago(o.lastSeen, now), { size: 4, align: 'right', fg: theme.muted });
          });
          p.text(`  ${[o.city, o.countryCode].filter(Boolean).join(', ')}${o.category ? ` · ${o.category}` : ''}`, {
            size: 1,
            fg: theme.muted,
          });
        }
      });
    });
  });
}

export function mapFooter(ui: Container, theme: Theme): void {
  ui.statusBar({
    size: 1,
    items: [
      { key: 'q', label: 'quit' },
      { key: 'm', label: 'dashboard' },
      { key: 'p', label: 'pause' },
    ],
    right: [
      { label: '◆ this server', color: hex(MAP_COLORS.server) },
      { label: '● critical', color: hex(MAP_COLORS.critical) },
      { label: '● high', color: hex(MAP_COLORS.high) },
      { label: '● medium', color: hex(MAP_COLORS.medium) },
      { label: '● low', color: hex(MAP_COLORS.low) },
      { label: 'geo: DB-IP', color: theme.muted },
    ],
    background: theme.surface,
  });
}
