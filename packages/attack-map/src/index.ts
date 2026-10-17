// The attack map every ThreatCrush surface draws: one land mask, one
// projection, one set of types, so the web, desktop, mobile, extension and TUI
// maps all show the same world with the same dots.
import { LAND_BITS_B64, LAND_COLS, LAND_NORTH, LAND_ROWS, LAND_SOUTH } from "./land-data";

export { LAND_COLS, LAND_ROWS, LAND_NORTH, LAND_SOUTH };

/** A source of attacks, aggregated by IP over the map's window. */
export interface AttackOrigin {
  ip: string;
  lat: number;
  lon: number;
  country?: string;
  /** ISO 3166-1 alpha-2. */
  countryCode?: string;
  city?: string;
  /** Events from this IP in the window. */
  count: number;
  /** Worst severity seen: critical | high | medium | low | info. */
  severity: Severity;
  /** ISO timestamp of the most recent event. */
  lastSeen: string;
  /** Which of our servers it hit (servers.id), when known. */
  serverId?: string;
  /** Most recent detection category, e.g. "ssh-brute-force". */
  category?: string;
}

/** One of our servers, where attacks land. */
export interface ServerPin {
  id: string;
  name: string;
  lat: number;
  lon: number;
  city?: string;
  country?: string;
  online?: boolean;
}

export interface AttackMapData {
  servers: ServerPin[];
  origins: AttackOrigin[];
  /** Window the origins cover, in minutes. */
  windowMinutes: number;
  generatedAt: string;
  /** True when the feed is canned demo data (no servers linked yet). */
  demo?: boolean;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Map palette, shared so every surface reads the same. Matches threatcrush.com. */
export const MAP_COLORS = {
  ocean: "#050505",
  land: "#123d1f",
  landBright: "#1f6b35",
  server: "#00ff41",
  critical: "#ff2d55",
  high: "#ff6b35",
  medium: "#ffb020",
  low: "#4fc3f7",
  info: "#8b949e",
  text: "#c9d1d9",
  textDim: "#8b949e",
} as const;

export function severityColor(s: Severity | string | undefined): string {
  return (MAP_COLORS as Record<string, string>)[s ?? "info"] ?? MAP_COLORS.info;
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

let landBits: Uint8Array | undefined;
function bits(): Uint8Array {
  if (!landBits) {
    // atob exists in browsers, React Native (Hermes) and Node 16+.
    const bin = atob(LAND_BITS_B64);
    landBits = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) landBits[i] = bin.charCodeAt(i);
  }
  return landBits;
}

/** Is mask cell (col, row) land? Out of range is ocean. */
export function isLandCell(col: number, row: number): boolean {
  if (col < 0 || row < 0 || col >= LAND_COLS || row >= LAND_ROWS) return false;
  const i = row * LAND_COLS + col;
  return (bits()[i >> 3] & (0x80 >> (i & 7))) !== 0;
}

/**
 * Is the point at fraction (fx, fy) of the map land? Samples the mask cell
 * under it, so any resolution can ask without knowing the mask size.
 */
export function isLandAt(fx: number, fy: number): boolean {
  return isLandCell(Math.floor(fx * LAND_COLS), Math.floor(fy * LAND_ROWS));
}

/** Equirectangular projection cropped to the mask: lat/lon -> fractions 0..1. */
export function project(lat: number, lon: number): { x: number; y: number } {
  const x = (((lon + 180) % 360) + 360) % 360 / 360;
  const y = (LAND_NORTH - Math.max(LAND_SOUTH, Math.min(LAND_NORTH, lat))) / (LAND_NORTH - LAND_SOUTH);
  return { x, y };
}

/** Width / height of the map, for sizing containers. */
export const MAP_ASPECT = 360 / (LAND_NORTH - LAND_SOUTH);

/**
 * Points along the great circle from a to b, as lat/lon, for drawing an arc.
 * Long arcs that cross the antimeridian come back split by the caller.
 */
export function greatCircle(
  a: { lat: number; lon: number },
  b: { lat: number; lon: number },
  steps = 48,
): Array<{ lat: number; lon: number }> {
  const rad = Math.PI / 180;
  const φ1 = a.lat * rad;
  const λ1 = a.lon * rad;
  const φ2 = b.lat * rad;
  const λ2 = b.lon * rad;
  const d =
    2 *
    Math.asin(
      Math.sqrt(Math.sin((φ2 - φ1) / 2) ** 2 + Math.cos(φ1) * Math.cos(φ2) * Math.sin((λ2 - λ1) / 2) ** 2),
    );
  if (d < 1e-9) return [a, b];
  const out: Array<{ lat: number; lon: number }> = [];
  for (let i = 0; i <= steps; i++) {
    const f = i / steps;
    const A = Math.sin((1 - f) * d) / Math.sin(d);
    const B = Math.sin(f * d) / Math.sin(d);
    const x = A * Math.cos(φ1) * Math.cos(λ1) + B * Math.cos(φ2) * Math.cos(λ2);
    const y = A * Math.cos(φ1) * Math.sin(λ1) + B * Math.cos(φ2) * Math.sin(λ2);
    const z = A * Math.sin(φ1) + B * Math.sin(φ2);
    out.push({ lat: Math.atan2(z, Math.sqrt(x * x + y * y)) / rad, lon: Math.atan2(y, x) / rad });
  }
  return out;
}

/**
 * The arc from an origin to a server as projected segments (fractions 0..1),
 * split where it wraps around the map edge so no line streaks across.
 */
export function arcSegments(
  from: { lat: number; lon: number },
  to: { lat: number; lon: number },
  steps = 48,
): Array<Array<{ x: number; y: number }>> {
  const segs: Array<Array<{ x: number; y: number }>> = [[]];
  let prev: { x: number; y: number } | undefined;
  for (const p of greatCircle(from, to, steps)) {
    const q = project(p.lat, p.lon);
    if (prev && Math.abs(q.x - prev.x) > 0.5) segs.push([]);
    segs[segs.length - 1].push(q);
    prev = q;
  }
  return segs.filter((s) => s.length > 1);
}

/** The server an origin's arc should land on: its own, else the nearest. */
export function targetServer(origin: AttackOrigin, servers: ServerPin[]): ServerPin | undefined {
  if (!servers.length) return undefined;
  const own = origin.serverId ? servers.find((s) => s.id === origin.serverId) : undefined;
  if (own) return own;
  let best = servers[0];
  let bestD = Infinity;
  for (const s of servers) {
    const d = (s.lat - origin.lat) ** 2 + (s.lon - origin.lon) ** 2;
    if (d < bestD) {
      bestD = d;
      best = s;
    }
  }
  return best;
}

/** Top countries by event count, for the legend beside every map. */
export function topCountries(origins: AttackOrigin[], limit = 5): Array<{ country: string; code?: string; count: number }> {
  const by = new Map<string, { country: string; code?: string; count: number }>();
  for (const o of origins) {
    const key = o.countryCode || o.country || "??";
    const row = by.get(key) ?? { country: o.country || o.countryCode || "Unknown", code: o.countryCode, count: 0 };
    row.count += o.count;
    by.set(key, row);
  }
  return [...by.values()].sort((a, b) => b.count - a.count).slice(0, limit);
}

/** Two-letter country code -> flag emoji. */
export function flag(code?: string): string {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return "🏴";
  const base = 0x1f1e6;
  const up = code.toUpperCase();
  return String.fromCodePoint(base + up.charCodeAt(0) - 65, base + up.charCodeAt(1) - 65);
}

/** Canned data for demo mode and screenshots: real-looking, clearly labelled. */
export function demoMapData(now = Date.now()): AttackMapData {
  const servers: ServerPin[] = [{ id: "demo", name: "demo-server", lat: 37.39, lon: -121.96, city: "Santa Clara", country: "US", online: true }];
  const seeds: Array<[string, number, number, string, string, string, Severity, string]> = [
    ["45.155.205.233", 52.37, 4.9, "Amsterdam", "Netherlands", "NL", "high", "ssh-brute-force"],
    ["218.92.0.112", 32.06, 118.78, "Nanjing", "China", "CN", "critical", "ssh-brute-force"],
    ["185.220.101.4", 50.11, 8.68, "Frankfurt", "Germany", "DE", "medium", "web-scanner"],
    ["103.145.13.9", 21.03, 105.85, "Hanoi", "Vietnam", "VN", "high", "sqli-attempt"],
    ["177.54.144.1", -23.55, -46.63, "São Paulo", "Brazil", "BR", "medium", "port-scan"],
    ["91.240.118.172", 55.75, 37.62, "Moscow", "Russia", "RU", "critical", "rce-attempt"],
    ["196.251.80.41", -26.2, 28.05, "Johannesburg", "South Africa", "ZA", "low", "web-scanner"],
    ["59.12.88.4", 37.57, 126.98, "Seoul", "South Korea", "KR", "high", "xss-attempt"],
    ["152.32.1.66", 1.35, 103.82, "Singapore", "Singapore", "SG", "medium", "path-traversal"],
    ["64.62.197.2", 40.71, -74.0, "New York", "United States", "US", "low", "port-scan"],
    ["122.161.4.12", 28.61, 77.21, "New Delhi", "India", "IN", "high", "ssh-brute-force"],
    ["41.216.188.9", 6.52, 3.38, "Lagos", "Nigeria", "NG", "medium", "credential-stuffing"],
  ];
  const origins = seeds.map(([ip, lat, lon, city, country, countryCode, severity, category], i) => ({
    ip,
    lat,
    lon,
    city,
    country,
    countryCode,
    severity,
    category,
    serverId: "demo",
    count: 3 + ((i * 37) % 90),
    lastSeen: new Date(now - i * 47_000).toISOString(),
  }));
  return { servers, origins, windowMinutes: 60, generatedAt: new Date(now).toISOString(), demo: true };
}
