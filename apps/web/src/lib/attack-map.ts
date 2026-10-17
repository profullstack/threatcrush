import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  type AttackMapData,
  type AttackOrigin,
  type ServerPin,
  type Severity,
  maxSeverity,
} from "@threatcrush/attack-map";
import { type GeoHit, isPublicIp, lookupIps } from "@/lib/geoip";
import { serverConnectionState } from "@/lib/server-status";

export const MAP_WINDOWS = [15, 60, 360, 1440] as const;
export const DEFAULT_WINDOW = 60;
/** Most detection rows read per snapshot, newest first. */
const ROW_LIMIT = 5000;
/** Most origins on one map. */
const ORIGIN_LIMIT = 400;
/** Identical requests within this window share one snapshot. */
const MEMO_MS = 2000;

export interface MapServerRow {
  id: string;
  name: string | null;
  hostname: string | null;
  ip_address: string | null;
  public_ip?: string | null;
  last_seen: string | null;
}

interface DetectionRow {
  source_ip: string | null;
  severity: Severity;
  server_id: string;
  occurrences: number | null;
  last_detected_at: string | null;
  detected_at: string;
  category: string | null;
  rule_id: string | null;
}

const SERVER_COLUMNS = "id, name, hostname, ip_address, last_seen, org_id, fleet_id";

/**
 * Servers in these orgs, with `public_ip` when the column exists. Migrations
 * are applied by hand, so the map must not break in the window between a
 * deploy and the migration: without the column it falls back to ip_address.
 */
export async function loadMapServers(
  admin: SupabaseClient,
  orgIds: string[],
): Promise<Array<MapServerRow & { org_id: string; fleet_id: string | null }>> {
  if (orgIds.length === 0) return [];
  const first = await admin.from("servers").select(`${SERVER_COLUMNS}, public_ip`).in("org_id", orgIds);
  if (!first.error) return (first.data ?? []) as unknown as Array<MapServerRow & { org_id: string; fleet_id: string | null }>;
  if (!/public_ip/.test(first.error.message)) throw new Error(`attack map servers: ${first.error.message}`);
  const second = await admin.from("servers").select(SERVER_COLUMNS).in("org_id", orgIds);
  if (second.error) throw new Error(`attack map servers: ${second.error.message}`);
  return (second.data ?? []) as unknown as Array<MapServerRow & { org_id: string; fleet_id: string | null }>;
}

export function parseWindow(raw: string | null): number {
  const n = Number(raw);
  return (MAP_WINDOWS as readonly number[]).includes(n) ? n : DEFAULT_WINDOW;
}

/** The address a server is reached at: what its heartbeat came from, else what the owner typed. */
export function serverAddress(s: MapServerRow): string | null {
  for (const ip of [s.public_ip, s.ip_address]) {
    const v = ip?.trim();
    if (v && isPublicIp(v)) return v;
  }
  return null;
}

/** 203.0.113.7 -> 203.0.113.0/24, 2001:db8:1:2::9 -> 2001:db8:1::/48. */
export function maskIp(ip: string): string {
  if (ip.includes(".") && !ip.includes(":")) return `${ip.split(".").slice(0, 3).join(".")}.0/24`;
  const groups = ip.split(":").filter(Boolean).slice(0, 3);
  return `${groups.join(":")}::/48`;
}

/**
 * Fold detection rows into one origin per source address. Pure, so the
 * aggregation is tested without a database.
 */
export function aggregateOrigins(
  rows: DetectionRow[],
  geo: Map<string, GeoHit>,
  opts: { mask?: boolean } = {},
): AttackOrigin[] {
  const by = new Map<string, AttackOrigin>();
  for (const r of rows) {
    const ip = r.source_ip?.trim();
    if (!ip) continue;
    const hit = geo.get(ip);
    if (!hit) continue;
    const key = opts.mask ? maskIp(ip) : ip;
    const seen = r.last_detected_at ?? r.detected_at;
    const count = Math.max(1, r.occurrences ?? 1);
    const prev = by.get(key);
    if (!prev) {
      by.set(key, {
        ip: key,
        lat: hit.lat,
        lon: hit.lon,
        city: hit.city,
        country: hit.country,
        countryCode: hit.countryCode,
        count,
        severity: r.severity,
        lastSeen: seen,
        serverId: r.server_id,
        category: r.category ?? r.rule_id ?? undefined,
      });
      continue;
    }
    prev.count += count;
    prev.severity = maxSeverity(prev.severity, r.severity);
    if (seen > prev.lastSeen) {
      prev.lastSeen = seen;
      prev.serverId = r.server_id;
      prev.category = r.category ?? r.rule_id ?? prev.category;
    }
  }
  return [...by.values()];
}

const memo = new Map<string, { at: number; data: Promise<AttackMapData> }>();

/**
 * The map for a set of servers: where each server is, and where everything
 * that attacked them in the last `windowMinutes` came from.
 *
 * `publicView` is for the unauthenticated homepage map: source addresses are
 * cut to their /24 (/48), servers are named by city, ids are opaque.
 */
export function buildAttackMap(
  admin: SupabaseClient,
  servers: MapServerRow[],
  windowMinutes: number,
  opts: { publicView?: boolean } = {},
): Promise<AttackMapData> {
  const key = `${opts.publicView ? "p" : "a"}:${windowMinutes}:${servers.map((s) => s.id).sort().join(",")}`;
  const now = Date.now();
  const hit = memo.get(key);
  if (hit && now - hit.at < MEMO_MS) return hit.data;
  if (memo.size > 500) {
    for (const [k, v] of memo) if (now - v.at >= MEMO_MS) memo.delete(k);
  }
  const data = build(admin, servers, windowMinutes, opts.publicView ?? false);
  memo.set(key, { at: now, data });
  data.catch(() => memo.delete(key));
  return data;
}

async function build(
  admin: SupabaseClient,
  servers: MapServerRow[],
  windowMinutes: number,
  publicView: boolean,
): Promise<AttackMapData> {
  const now = Date.now();
  const since = new Date(now - windowMinutes * 60_000).toISOString();
  const ids = servers.map((s) => s.id);

  let rows: DetectionRow[] = [];
  if (ids.length > 0) {
    const { data, error } = await admin
      .from("detections")
      .select(
        "source_ip, severity, server_id, occurrences, last_detected_at, detected_at, rule_id, category:raw_metadata->>category",
      )
      .in("server_id", ids)
      .not("source_ip", "is", null)
      .gte("last_detected_at", since)
      .order("last_detected_at", { ascending: false })
      .limit(ROW_LIMIT);
    if (error) throw new Error(`attack map detections: ${error.message}`);
    rows = (data ?? []) as unknown as DetectionRow[];
  }

  // Newest sources first, so the cap drops the stalest.
  const ips: string[] = [];
  const seenIps = new Set<string>();
  for (const r of rows) {
    const ip = r.source_ip?.trim();
    if (ip && !seenIps.has(ip) && isPublicIp(ip)) {
      seenIps.add(ip);
      ips.push(ip);
    }
  }
  const addrs = servers.map(serverAddress);
  const geo = await lookupIps([...ips.slice(0, ORIGIN_LIMIT * 4), ...addrs.filter((a): a is string => !!a)]);

  const pins: ServerPin[] = [];
  const pinId = new Map<string, string>();
  servers.forEach((s, i) => {
    const addr = addrs[i];
    const g = addr ? geo.get(addr) : undefined;
    if (!g) return;
    const id = publicView ? `s${i + 1}` : s.id;
    pinId.set(s.id, id);
    pins.push({
      id,
      name: publicView ? g.city || g.country || "ThreatCrush" : s.name || s.hostname || "server",
      lat: g.lat,
      lon: g.lon,
      city: g.city,
      country: g.countryCode ?? g.country,
      online: serverConnectionState(s.last_seen, now) === "online",
    });
  });

  const origins = aggregateOrigins(rows, geo, { mask: publicView })
    .sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1))
    .slice(0, ORIGIN_LIMIT)
    .map((o) => ({ ...o, serverId: o.serverId ? pinId.get(o.serverId) : undefined }));

  return { servers: pins, origins, windowMinutes, generatedAt: new Date(now).toISOString() };
}
