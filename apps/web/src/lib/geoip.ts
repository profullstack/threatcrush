import "server-only";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, rename, stat, unlink } from "node:fs/promises";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { createGunzip } from "node:zlib";
import { Reader, type CityResponse } from "mmdb-lib";

/**
 * IP geolocation for the attack map, from DB-IP's free "IP to City Lite"
 * database (CC BY 4.0: pages that show the result credit DB-IP).
 *
 * Nothing ships in the image: the first lookup downloads this month's file
 * (~60 MB gzipped) into GEOIP_DIR, and it is refreshed when a month old.
 * GEOIP_DB_PATH points at an existing .mmdb instead (any MaxMind-format City
 * database works, GeoLite2 included). Until the file is ready, or when the
 * download fails, lookups return null and the maps simply show fewer origins.
 */

export interface GeoHit {
  lat: number;
  lon: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

const REFRESH_MS = 32 * 24 * 60 * 60 * 1000;
const RETRY_MS = 10 * 60 * 1000;
const CACHE_MAX = 50_000;

let reader: Reader<CityResponse> | null = null;
let loading: Promise<void> | null = null;
let lastFailure = 0;
let loadedAt = 0;
const cache = new Map<string, GeoHit | null>();

/** Private, loopback, link-local, CGNAT, multicast and documentation ranges never geolocate. */
export function isPublicIp(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 192 && b === 0) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  if (v === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return false;
    if (/^f[cd]/.test(lower) || /^fe[89ab]/.test(lower) || lower.startsWith("ff")) return false;
    if (lower.startsWith("2001:db8")) return false;
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPublicIp(mapped[1]);
    return true;
  }
  return false;
}

function dbDir(): string {
  return process.env["GEOIP_DIR"] || path.join(tmpdir(), "threatcrush-geoip");
}

function monthStamp(offset: number): string {
  const d = new Date();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() - offset);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

async function download(dest: string): Promise<void> {
  // DB-IP publishes on the 1st; early in the month the new file may not exist yet.
  for (const offset of [0, 1]) {
    const url = `https://download.db-ip.com/free/dbip-city-lite-${monthStamp(offset)}.mmdb.gz`;
    const res = await fetch(url);
    if (!res.ok || !res.body) continue;
    const tmp = `${dest}.${process.pid}.part`;
    try {
      await pipeline(Readable.fromWeb(res.body as unknown as WebReadableStream), createGunzip(), createWriteStream(tmp));
      await rename(tmp, dest);
      return;
    } catch (err) {
      await unlink(tmp).catch(() => {});
      throw err;
    }
  }
  throw new Error("no DB-IP city lite file for this month or last");
}

async function load(): Promise<void> {
  const explicit = process.env["GEOIP_DB_PATH"];
  let file = explicit;
  if (!file) {
    const dir = dbDir();
    await mkdir(dir, { recursive: true });
    file = path.join(dir, "dbip-city-lite.mmdb");
    const age = await stat(file).then((s) => Date.now() - s.mtimeMs, () => Infinity);
    if (age > REFRESH_MS) {
      try {
        await download(file);
      } catch (err) {
        // A stale file still beats none.
        if (age === Infinity) throw err;
        console.error("geoip: refresh failed, keeping the old database:", err);
      }
    }
  }
  reader = new Reader<CityResponse>(await readFile(file));
  loadedAt = Date.now();
  cache.clear();
}

/** Start loading the database if it isn't loaded (or due a refresh). Never throws. */
export function ensureGeoip(): Promise<void> {
  const stale = reader && !process.env["GEOIP_DB_PATH"] && Date.now() - loadedAt > REFRESH_MS;
  if ((reader && !stale) || loading) return loading ?? Promise.resolve();
  if (!reader && Date.now() - lastFailure < RETRY_MS) return Promise.resolve();
  loading = load()
    .catch((err) => {
      lastFailure = Date.now();
      console.error("geoip: database unavailable:", err);
    })
    .finally(() => {
      loading = null;
    });
  return loading;
}

/** Whether lookups can answer yet. */
export function geoipReady(): boolean {
  return reader !== null;
}

/** Look up one address. Null for private addresses, misses, or no database. */
export function lookupIp(ip: string): GeoHit | null {
  if (!reader || !isPublicIp(ip)) return null;
  const hit = cache.get(ip);
  if (hit !== undefined) return hit;
  let out: GeoHit | null = null;
  try {
    const r = reader.get(ip);
    const loc = r?.location;
    if (loc && typeof loc.latitude === "number" && typeof loc.longitude === "number") {
      out = {
        lat: loc.latitude,
        lon: loc.longitude,
        city: r?.city?.names?.en,
        country: r?.country?.names?.en,
        countryCode: r?.country?.iso_code,
      };
    }
  } catch {
    out = null;
  }
  if (cache.size >= CACHE_MAX) cache.clear();
  cache.set(ip, out);
  return out;
}

/**
 * Look up many addresses, waiting (up to `waitMs`) for the database on a cold
 * start so the first map isn't empty.
 */
export async function lookupIps(ips: string[], waitMs = 8000): Promise<Map<string, GeoHit>> {
  if (!reader) {
    await Promise.race([ensureGeoip(), new Promise((r) => setTimeout(r, waitMs))]);
  } else {
    void ensureGeoip();
  }
  const out = new Map<string, GeoHit>();
  for (const ip of ips) {
    const hit = lookupIp(ip);
    if (hit) out.set(ip, hit);
  }
  return out;
}

export const GEOIP_ATTRIBUTION = { text: "IP Geolocation by DB-IP", url: "https://db-ip.com" } as const;
