// The attack map as terminal cells: braille dots (2x4 per cell) for the land,
// arcs drawn as comets that travel from each origin to the server it hit, and
// a glyph per origin and server. Pure: returns cells, the TUI paints them.
import {
  type AttackMapData,
  type AttackOrigin,
  MAP_COLORS,
  SEVERITY_RANK,
  arcSegments,
  isLandAt,
  project,
  severityColor,
  targetServer,
} from "./index";

export interface MapCell {
  ch: string;
  fg: string;
  bold?: boolean;
}

export interface CellMapOptions {
  /** Milliseconds; drives the comets. Pass Date.now() each frame. */
  now?: number;
  /** Origins seen within this many ms get a live arc. Default 10 minutes. */
  liveMs?: number;
  /** Most arcs to draw at once (busiest first). Default 24. */
  maxArcs?: number;
}

const BRAILLE = 0x2800;
// Bit for dot (dx, dy) inside a braille cell.
const DOT = [
  [0x01, 0x08],
  [0x02, 0x10],
  [0x04, 0x20],
  [0x40, 0x80],
];

/** How far along its arc (0..1) an origin's comet is at `now`; staggered per IP. */
export function cometPhase(ip: string, now: number, periodMs = 2400): number {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
  return ((now + (h % periodMs)) % periodMs) / periodMs;
}

/** Origins worth an arc: recent, busiest and worst first. */
export function liveOrigins(data: AttackMapData, now: number, liveMs = 600_000, max = 24): AttackOrigin[] {
  return data.origins
    .filter((o) => now - Date.parse(o.lastSeen) <= liveMs)
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count)
    .slice(0, max);
}

export function renderCells(data: AttackMapData, cols: number, rows: number, opts: CellMapOptions = {}): MapCell[][] {
  const now = opts.now ?? Date.now();
  const W = cols * 2;
  const H = rows * 4;
  const mask = new Uint8Array(cols * rows);
  const tint: (string | undefined)[] = new Array(cols * rows);
  const rank = new Int8Array(cols * rows).fill(-1);

  const dot = (px: number, py: number, color?: string, r = -1) => {
    const x = Math.round(px);
    const y = Math.round(py);
    if (x < 0 || y < 0 || x >= W || y >= H) return;
    const c = (y >> 2) * cols + (x >> 1);
    mask[c] |= DOT[y & 3][x & 1];
    if (color && r >= rank[c]) {
      tint[c] = color;
      rank[c] = r;
    }
  };

  // Land: a checkerboard of dots (half of each cell) reads as a map, not a blob.
  for (let y = 0; y < H; y++) {
    for (let x = y & 1; x < W; x += 2) {
      if (isLandAt((x + 0.5) / W, (y + 0.5) / H)) dot(x, y);
    }
  }

  // Comets: a short bright tail moving origin -> server.
  for (const o of liveOrigins(data, now, opts.liveMs, opts.maxArcs)) {
    const s = targetServer(o, data.servers);
    if (!s) continue;
    const pts = arcSegments(o, s, 64).flat();
    const head = Math.floor(cometPhase(o.ip, now) * pts.length);
    const color = severityColor(o.severity);
    for (let i = Math.max(0, head - 10); i <= head && i < pts.length; i++) {
      dot(pts[i].x * W, pts[i].y * H, color, SEVERITY_RANK[o.severity]);
    }
  }

  const cells: MapCell[][] = [];
  for (let r = 0; r < rows; r++) {
    const row: MapCell[] = [];
    for (let c = 0; c < cols; c++) {
      const i = r * cols + c;
      row.push({ ch: mask[i] ? String.fromCharCode(BRAILLE + mask[i]) : " ", fg: tint[i] ?? MAP_COLORS.landBright });
    }
    cells.push(row);
  }

  const put = (lat: number, lon: number, ch: string, fg: string) => {
    const p = project(lat, lon);
    const c = Math.min(cols - 1, Math.floor(p.x * cols));
    const r = Math.min(rows - 1, Math.floor(p.y * rows));
    cells[r][c] = { ch, fg, bold: true };
    return { c, r };
  };

  // Origins: worst drawn last so it wins a shared cell; recent ones blink.
  const byRank = [...data.origins].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  for (const o of byRank) {
    const fresh = now - Date.parse(o.lastSeen) < 60_000;
    const ch = fresh && Math.floor(now / 500) % 2 ? "◉" : o.count >= 50 ? "●" : "•";
    put(o.lat, o.lon, ch, severityColor(o.severity));
  }

  // Servers on top, with their name where it fits.
  for (const s of data.servers) {
    const { c, r } = put(s.lat, s.lon, "◆", s.online === false ? MAP_COLORS.textDim : MAP_COLORS.server);
    const label = ` ${s.name}`;
    const start = c + label.length < cols ? c + 1 : c - label.length;
    for (let k = 0; k < label.length; k++) {
      const x = start + k;
      if (x >= 0 && x < cols && x !== c) cells[r][x] = { ch: label[k], fg: MAP_COLORS.server, bold: true };
    }
  }
  return cells;
}
