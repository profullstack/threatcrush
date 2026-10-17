// The attack map as a real image, for terminals that draw pixels (hqterm,
// iTerm2, WezTerm, Kitty, Ghostty). Pure Node: a tiny RGBA rasterizer and a
// PNG encoder on node:zlib, so the CLI gains no native dependency.
import { deflateSync } from "node:zlib";
import {
  type AttackMapData,
  MAP_COLORS,
  SEVERITY_RANK,
  arcSegments,
  isLandAt,
  project,
  severityColor,
  targetServer,
} from "../index";
import { cometPhase, liveOrigins } from "../braille";

type RGB = [number, number, number];

function hex(c: string): RGB {
  const n = parseInt(c.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

class Raster {
  readonly px: Uint8Array;
  constructor(
    readonly w: number,
    readonly h: number,
    bg: RGB,
  ) {
    this.px = new Uint8Array(w * h * 4);
    for (let i = 0; i < w * h; i++) this.px.set([bg[0], bg[1], bg[2], 255], i * 4);
  }
  /** Alpha-blend one pixel. */
  blend(x: number, y: number, c: RGB, a: number) {
    x = Math.round(x);
    y = Math.round(y);
    if (x < 0 || y < 0 || x >= this.w || y >= this.h || a <= 0) return;
    const i = (y * this.w + x) * 4;
    const k = Math.min(1, a);
    for (let j = 0; j < 3; j++) this.px[i + j] = this.px[i + j] + (c[j] - this.px[i + j]) * k;
  }
  /** Filled disc with a soft edge and an optional glow halo. */
  disc(cx: number, cy: number, r: number, c: RGB, a = 1, glow = 0) {
    const R = r + glow;
    for (let y = Math.floor(cy - R); y <= Math.ceil(cy + R); y++) {
      for (let x = Math.floor(cx - R); x <= Math.ceil(cx + R); x++) {
        const d = Math.hypot(x - cx, y - cy);
        if (d <= r) this.blend(x, y, c, a * Math.min(1, r - d + 0.5));
        else if (glow && d <= R) this.blend(x, y, c, a * 0.35 * (1 - (d - r) / glow) ** 2);
      }
    }
  }
  /** Ring (outline circle) of width `w`. */
  ring(cx: number, cy: number, r: number, w: number, c: RGB, a: number) {
    for (let y = Math.floor(cy - r - w); y <= Math.ceil(cy + r + w); y++) {
      for (let x = Math.floor(cx - r - w); x <= Math.ceil(cx + r + w); x++) {
        const d = Math.abs(Math.hypot(x - cx, y - cy) - r);
        if (d < w) this.blend(x, y, c, a * (1 - d / w));
      }
    }
  }
  png(): Buffer {
    const raw = Buffer.alloc((this.w * 4 + 1) * this.h);
    for (let y = 0; y < this.h; y++) {
      raw[y * (this.w * 4 + 1)] = 0;
      Buffer.from(this.px.buffer, y * this.w * 4, this.w * 4).copy(raw, y * (this.w * 4 + 1) + 1);
    }
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(this.w, 0);
    ihdr.writeUInt32BE(this.h, 4);
    ihdr.set([8, 6, 0, 0, 0], 8);
    return Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      chunk("IHDR", ihdr),
      chunk("IDAT", deflateSync(raw, { level: 6 })),
      chunk("IEND", Buffer.alloc(0)),
    ]);
  }
}

const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(b: Buffer): number {
  let c = 0xffffffff;
  for (const x of b) c = CRC[(c ^ x) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

export interface PngMapOptions {
  now?: number;
  liveMs?: number;
  maxArcs?: number;
}

/** Render the map at `width` x `height` pixels and return PNG bytes. */
export function renderPng(data: AttackMapData, width: number, height: number, opts: PngMapOptions = {}): Buffer {
  const now = opts.now ?? Date.now();
  const r = new Raster(width, height, hex(MAP_COLORS.ocean));
  const land = hex(MAP_COLORS.land);
  const landHi = hex(MAP_COLORS.landBright);

  // Dot-matrix land, the same look as the web map.
  const pitch = Math.max(3, Math.round(width / 180));
  const dotR = pitch * 0.32;
  for (let y = pitch / 2; y < height; y += pitch) {
    for (let x = pitch / 2; x < width; x += pitch) {
      if (isLandAt(x / width, y / height)) r.disc(x, y, dotR, (x * 7 + y * 3) % 11 ? land : landHi, 1);
    }
  }

  const at = (lat: number, lon: number) => {
    const p = project(lat, lon);
    return { x: p.x * width, y: p.y * height };
  };

  // Faint full arcs, then a bright comet on each.
  for (const o of liveOrigins(data, now, opts.liveMs, opts.maxArcs)) {
    const s = targetServer(o, data.servers);
    if (!s) continue;
    const c = hex(severityColor(o.severity));
    const segs = arcSegments(o, s, 96);
    for (const seg of segs) {
      for (let i = 1; i < seg.length; i++) line(r, seg[i - 1], seg[i], width, height, c, 0.18);
    }
    const pts = segs.flat();
    const head = cometPhase(o.ip, now) * (pts.length - 1);
    const h = Math.floor(head);
    for (let i = Math.max(0, h - 18); i <= h; i++) {
      const t = 1 - (h - i) / 18;
      r.disc(pts[i].x * width, pts[i].y * height, 1 + t * 1.4, c, t * 0.9);
    }
    if (pts[h]) r.disc(pts[h].x * width, pts[h].y * height, 2.4, c, 1, 5);
  }

  // Origins: size by volume, ring pulse when seen in the last minute.
  const origins = [...data.origins].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  for (const o of origins) {
    const p = at(o.lat, o.lon);
    const c = hex(severityColor(o.severity));
    const size = 1.6 + Math.min(4, Math.log2(1 + o.count) * 0.6);
    r.disc(p.x, p.y, size, c, 0.95, 4);
    if (now - Date.parse(o.lastSeen) < 60_000) {
      const t = (now % 1600) / 1600;
      r.ring(p.x, p.y, size + t * 14, 1.2, c, 1 - t);
    }
  }

  // Our servers: bright green with two radar rings.
  const g = hex(MAP_COLORS.server);
  for (const s of data.servers) {
    const p = at(s.lat, s.lon);
    const dim = s.online === false;
    for (const off of [0, 0.5]) {
      const t = ((now / 2000 + off) % 1 + 1) % 1;
      if (!dim) r.ring(p.x, p.y, 4 + t * 22, 1.4, g, (1 - t) * 0.8);
    }
    r.disc(p.x, p.y, 4, dim ? hex(MAP_COLORS.textDim) : g, 1, 8);
    r.disc(p.x, p.y, 1.6, [255, 255, 255], 0.9);
  }
  return r.png();
}

function line(
  r: Raster,
  a: { x: number; y: number },
  b: { x: number; y: number },
  w: number,
  h: number,
  c: RGB,
  alpha: number,
) {
  const x0 = a.x * w;
  const y0 = a.y * h;
  const x1 = b.x * w;
  const y1 = b.y * h;
  const n = Math.max(1, Math.ceil(Math.hypot(x1 - x0, y1 - y0)));
  for (let i = 0; i <= n; i++) r.blend(x0 + ((x1 - x0) * i) / n, y0 + ((y1 - y0) * i) / n, c, alpha);
}
