// The attack map on a <canvas>, for the web, desktop and extension. No
// framework: create a renderer on a canvas, feed it data, it animates itself.
//
//   const map = createAttackMap(canvas);
//   map.setData(data);           // whenever new data arrives
//   map.destroy();               // on unmount
import {
  type AttackMapData,
  type AttackOrigin,
  type ServerPin,
  MAP_COLORS,
  SEVERITY_RANK,
  arcSegments,
  isLandAt,
  project,
  severityColor,
  targetServer,
} from "./index";

export interface AttackMapOptions {
  /** Origins seen within this many ms get a live arc. Default 15 minutes. */
  liveMs?: number;
  /** Most arcs at once. Default 40. */
  maxArcs?: number;
  /** Land dot pitch in CSS pixels. Default: width / 160, at least 4. */
  dotPitch?: number;
  /** Respect prefers-reduced-motion by drawing a still frame. Default true. */
  reducedMotion?: boolean;
}

export type MapHit = { kind: "origin"; origin: AttackOrigin } | { kind: "server"; server: ServerPin };

export interface AttackMapRenderer {
  setData(data: AttackMapData): void;
  /** What is under CSS pixel (x, y) of the canvas, for tooltips. */
  hitTest(x: number, y: number): MapHit | undefined;
  destroy(): void;
}

interface Flight {
  origin: AttackOrigin;
  server: ServerPin;
  /** Projected path in fractions. */
  path: Array<{ x: number; y: number }>;
  /** ms per trip, and a per-IP offset so they don't fire in step. */
  period: number;
  offset: number;
}

const TAU = Math.PI * 2;

function hashIp(ip: string): number {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
  return h;
}

/** A lifted arc for short hops, the true great circle when it wraps the map. */
function flightPath(o: AttackOrigin, s: ServerPin): Array<{ x: number; y: number }> {
  const a = project(o.lat, o.lon);
  const b = project(s.lat, s.lon);
  if (Math.abs(a.x - b.x) > 0.5) return arcSegments(o, s, 64).flat();
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const dist = Math.hypot(b.x - a.x, b.y - a.y);
  // Lift toward the top of the map, more for longer hops.
  const cx = mx;
  const cy = my - dist * 0.45;
  const pts: Array<{ x: number; y: number }> = [];
  for (let i = 0; i <= 64; i++) {
    const t = i / 64;
    const u = 1 - t;
    pts.push({ x: u * u * a.x + 2 * u * t * cx + t * t * b.x, y: u * u * a.y + 2 * u * t * cy + t * t * b.y });
  }
  return pts;
}

function rgba(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

export function createAttackMap(canvas: HTMLCanvasElement, opts: AttackMapOptions = {}): AttackMapRenderer {
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("canvas 2d context unavailable");
  const liveMs = opts.liveMs ?? 15 * 60_000;
  const maxArcs = opts.maxArcs ?? 40;
  const still =
    (opts.reducedMotion ?? true) &&
    typeof matchMedia === "function" &&
    matchMedia("(prefers-reduced-motion: reduce)").matches;

  let data: AttackMapData | undefined;
  let flights: Flight[] = [];
  let w = 0;
  let h = 0;
  let dpr = 1;
  let land: HTMLCanvasElement | undefined;
  let raf = 0;
  let destroyed = false;
  // Origins we have not seen before flash bright for a moment.
  const seen = new Map<string, number>();

  function buildLand() {
    land = document.createElement("canvas");
    land.width = Math.max(1, Math.round(w * dpr));
    land.height = Math.max(1, Math.round(h * dpr));
    const g = land.getContext("2d")!;
    g.scale(dpr, dpr);
    const pitch = opts.dotPitch ?? Math.max(4, w / 160);
    const r = pitch * 0.3;
    for (let y = pitch / 2; y < h; y += pitch) {
      for (let x = pitch / 2; x < w; x += pitch) {
        if (!isLandAt(x / w, y / h)) continue;
        // A little shimmer: a few brighter dots, stable per position.
        g.fillStyle = (Math.round(x / pitch) * 7 + Math.round(y / pitch) * 13) % 17 === 0 ? MAP_COLORS.landBright : MAP_COLORS.land;
        g.beginPath();
        g.arc(x, y, r, 0, TAU);
        g.fill();
      }
    }
  }

  function resize() {
    const rect = canvas.getBoundingClientRect();
    dpr = Math.min(2, globalThis.devicePixelRatio || 1);
    w = Math.max(1, rect.width);
    h = Math.max(1, rect.height);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    buildLand();
    if (still) draw(performance.now());
  }

  function rebuildFlights() {
    if (!data) return;
    const now = Date.now();
    flights = data.origins
      .filter((o) => now - Date.parse(o.lastSeen) <= liveMs)
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count)
      .slice(0, maxArcs)
      .flatMap((o) => {
        const s = targetServer(o, data!.servers);
        if (!s) return [];
        const hsh = hashIp(o.ip);
        // Busier sources fire faster: 1.6s to 4s a trip.
        const period = 4000 - Math.min(2400, Math.log2(1 + o.count) * 300);
        return [{ origin: o, server: s, path: flightPath(o, s), period, offset: hsh % period }];
      });
  }

  function draw(t: number) {
    if (!land || !data) {
      ctx!.clearRect(0, 0, canvas.width, canvas.height);
      if (land) ctx!.drawImage(land, 0, 0);
      return;
    }
    const c = ctx!;
    c.setTransform(1, 0, 0, 1, 0, 0);
    c.fillStyle = MAP_COLORS.ocean;
    c.fillRect(0, 0, canvas.width, canvas.height);
    c.drawImage(land, 0, 0);
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    const now = Date.now();

    // Arcs: faint full path plus a comet; an impact ripple at the server.
    c.lineCap = "round";
    for (const f of flights) {
      const color = severityColor(f.origin.severity);
      const n = f.path.length;
      c.strokeStyle = rgba(color, 0.12);
      c.lineWidth = 1;
      c.beginPath();
      for (let i = 0; i < n; i++) {
        const p = f.path[i];
        const x = p.x * w;
        const y = p.y * h;
        if (i && Math.abs(p.x - f.path[i - 1].x) > 0.5) c.moveTo(x, y);
        else if (i) c.lineTo(x, y);
        else c.moveTo(x, y);
      }
      c.stroke();

      const phase = still ? 0.85 : ((t + f.offset) % f.period) / f.period;
      // 80% of the period in flight, the rest is the impact.
      const fly = Math.min(1, phase / 0.8);
      const head = Math.floor(fly * (n - 1));
      const tail = Math.max(0, head - Math.round(n * 0.22));
      for (let i = tail + 1; i <= head; i++) {
        const a = f.path[i - 1];
        const b = f.path[i];
        if (Math.abs(a.x - b.x) > 0.5) continue;
        const k = (i - tail) / (head - tail + 1);
        c.strokeStyle = rgba(color, 0.15 + 0.85 * k);
        c.lineWidth = 0.6 + 1.8 * k;
        c.beginPath();
        c.moveTo(a.x * w, a.y * h);
        c.lineTo(b.x * w, b.y * h);
        c.stroke();
      }
      if (phase < 0.8) {
        const p = f.path[head];
        const g = c.createRadialGradient(p.x * w, p.y * h, 0, p.x * w, p.y * h, 7);
        g.addColorStop(0, rgba("#ffffff", 0.95));
        g.addColorStop(0.3, rgba(color, 0.9));
        g.addColorStop(1, rgba(color, 0));
        c.fillStyle = g;
        c.beginPath();
        c.arc(p.x * w, p.y * h, 7, 0, TAU);
        c.fill();
      } else {
        const k = (phase - 0.8) / 0.2;
        const s = project(f.server.lat, f.server.lon);
        c.strokeStyle = rgba(color, 1 - k);
        c.lineWidth = 1.5;
        c.beginPath();
        c.arc(s.x * w, s.y * h, 4 + k * 16, 0, TAU);
        c.stroke();
      }
    }

    // Origins, worst on top. New ones flash.
    const origins = [...data.origins].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
    for (const o of origins) {
      const p = project(o.lat, o.lon);
      const x = p.x * w;
      const y = p.y * h;
      const color = severityColor(o.severity);
      const size = 2 + Math.min(5, Math.log2(1 + o.count) * 0.7);
      const born = seen.get(o.ip) ?? 0;
      const flash = Math.max(0, 1 - (now - born) / 2500);
      const glowR = size * 3.2 + flash * 18;
      const g = c.createRadialGradient(x, y, 0, x, y, glowR);
      g.addColorStop(0, rgba(color, 0.55 + flash * 0.4));
      g.addColorStop(1, rgba(color, 0));
      c.fillStyle = g;
      c.beginPath();
      c.arc(x, y, glowR, 0, TAU);
      c.fill();
      c.fillStyle = color;
      c.beginPath();
      c.arc(x, y, size, 0, TAU);
      c.fill();
      if (!still && now - Date.parse(o.lastSeen) < 90_000) {
        const k = ((t + hashIp(o.ip)) % 1800) / 1800;
        c.strokeStyle = rgba(color, 0.8 * (1 - k));
        c.lineWidth = 1.2;
        c.beginPath();
        c.arc(x, y, size + k * 14, 0, TAU);
        c.stroke();
      }
    }

    // Our servers: radar sweep rings and a label.
    c.font = "600 11px 'JetBrains Mono', ui-monospace, monospace";
    c.textBaseline = "middle";
    for (const s of data.servers) {
      const p = project(s.lat, s.lon);
      const x = p.x * w;
      const y = p.y * h;
      const color = s.online === false ? MAP_COLORS.textDim : MAP_COLORS.server;
      if (!still && s.online !== false) {
        for (const off of [0, 0.5]) {
          const k = ((t / 2600 + off) % 1 + 1) % 1;
          c.strokeStyle = rgba(color, 0.7 * (1 - k));
          c.lineWidth = 1.4;
          c.beginPath();
          c.arc(x, y, 5 + k * 26, 0, TAU);
          c.stroke();
        }
      }
      const g = c.createRadialGradient(x, y, 0, x, y, 16);
      g.addColorStop(0, rgba(color, 0.7));
      g.addColorStop(1, rgba(color, 0));
      c.fillStyle = g;
      c.beginPath();
      c.arc(x, y, 16, 0, TAU);
      c.fill();
      c.save();
      c.translate(x, y);
      c.rotate(Math.PI / 4);
      c.fillStyle = color;
      c.fillRect(-4, -4, 8, 8);
      c.fillStyle = "#ffffff";
      c.fillRect(-1.5, -1.5, 3, 3);
      c.restore();
    }

    // Labels last, each where it overlaps no label already drawn: right of the
    // marker, then left, then below and above. Servers in nearby cities (dev2
    // in Buffalo, seed1 in Montreal) used to print over each other.
    const placed: Array<{ x: number; y: number; w: number; h: number }> = [];
    const clash = (r: { x: number; y: number; w: number; h: number }) =>
      r.x < 0 || r.y < 0 || r.x + r.w > w || r.y + r.h > h ||
      placed.some((o) => r.x < o.x + o.w && o.x < r.x + r.w && r.y < o.y + o.h && o.y < r.y + r.h);
    for (const s of data.servers) {
      const p = project(s.lat, s.lon);
      const x = p.x * w;
      const y = p.y * h;
      const tw = c.measureText(s.name).width;
      const spots = [
        { x: x + 8, y: y - 8 },
        { x: x - 16 - tw, y: y - 8 },
        { x: x - tw / 2 - 4, y: y + 10 },
        { x: x - tw / 2 - 4, y: y - 26 },
      ];
      const spot = spots.map((o) => ({ ...o, w: tw + 8, h: 16 })).find((r) => !clash(r));
      if (!spot) continue;
      placed.push(spot);
      c.fillStyle = rgba(MAP_COLORS.ocean, 0.75);
      c.fillRect(spot.x, spot.y, spot.w, spot.h);
      c.fillStyle = s.online === false ? MAP_COLORS.textDim : MAP_COLORS.server;
      c.fillText(s.name, spot.x + 4, spot.y + 8);
    }
  }

  function loop(t: number) {
    if (destroyed) return;
    draw(t);
    raf = requestAnimationFrame(loop);
  }

  const ro = typeof ResizeObserver === "function" ? new ResizeObserver(() => resize()) : undefined;
  ro?.observe(canvas);
  resize();
  if (!still) raf = requestAnimationFrame(loop);

  return {
    setData(next) {
      const now = Date.now();
      for (const o of next.origins) if (!seen.has(o.ip)) seen.set(o.ip, data ? now : 0);
      if (seen.size > 5000) {
        const keep = new Set(next.origins.map((o) => o.ip));
        for (const ip of seen.keys()) if (!keep.has(ip)) seen.delete(ip);
      }
      data = next;
      rebuildFlights();
      if (still) draw(performance.now());
    },
    hitTest(x, y) {
      if (!data) return undefined;
      for (const s of data.servers) {
        const p = project(s.lat, s.lon);
        if (Math.hypot(p.x * w - x, p.y * h - y) < 10) return { kind: "server", server: s };
      }
      let best: AttackOrigin | undefined;
      let bestD = 12;
      for (const o of data.origins) {
        const p = project(o.lat, o.lon);
        const d = Math.hypot(p.x * w - x, p.y * h - y);
        if (d < bestD) {
          bestD = d;
          best = o;
        }
      }
      return best ? { kind: "origin", origin: best } : undefined;
    },
    destroy() {
      destroyed = true;
      cancelAnimationFrame(raf);
      ro?.disconnect();
    },
  };
}
