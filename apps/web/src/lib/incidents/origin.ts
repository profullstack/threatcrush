import "server-only";
import { isIP } from "node:net";
import type { SupabaseClient } from "@supabase/supabase-js";
import { parseInventory } from "@profullstack/fleet";
import { isPublicIp, lookupAsn, lookupIps, type AsnHit, type GeoHit } from "@/lib/geoip";
import { githubActionsChecker } from "@/lib/github-actions-ranges";

/**
 * Where a login (or any detection with a source address) came from, in words
 * a person on the phone can act on: one of the org's own machines (so most
 * likely its own automation), a private address, or an outside network with
 * its city, country and owner, flagged as NOT one of the org's servers (so
 * possibly a compromise).
 *
 * Own machines are the org's ThreatCrush servers (public_ip from heartbeats,
 * ip_address as typed) plus every device in its OpenDevice inventory, which
 * covers boxes that run no daemon. Never throws: a lookup that fails just
 * gives a plainer label.
 */

export interface OriginFacts {
  ip: string;
  /** The org's own machine at this address, when there is one. */
  own?: string | null;
  geo?: GeoHit | null;
  asn?: AsnHit | null;
  /** The address is in GitHub's published Actions runner ranges (api.github.com/meta). */
  githubActions?: boolean;
  /**
   * The authorized_keys comment of the deploy key the login used, when the
   * daemon found the key and its comment marks automation.
   */
  deployKey?: string | null;
}

/** Microsoft's network, where GitHub-hosted Actions runners live. */
const MICROSOFT_ASN = 8075;

/** The suffix that marks a login as known automation: never paged. */
export const KNOWN_AUTOMATION = "known automation, not paged";

const NOT_DEPLOY_KEY = "a GitHub Actions runner, but the key is not a known deploy key";

export function describeOrigin(o: OriginFacts): string {
  if (o.own) return `From ${o.own} (${o.ip}), one of your own servers`;
  if (!isPublicIp(o.ip)) return `From ${o.ip}, a private or local address`;
  // Known only with both: GitHub's own published runner range AND one of our
  // deploy keys. Either alone still pages: anyone can rent a GitHub runner,
  // and a person's key used from a runner is the stolen-key pattern.
  if (o.githubActions && o.deployKey) {
    return `From ${o.ip}, a GitHub Actions runner deploying with the key "${o.deployKey}", ${KNOWN_AUTOMATION}`;
  }
  const place = [o.geo?.city, o.geo?.country].filter(Boolean).join(", ");
  const ghNote = o.githubActions ? `, ${NOT_DEPLOY_KEY}` : o.asn?.asn === MICROSOFT_ASN ? ", may be GitHub Actions" : "";
  const net = o.asn
    ? `${o.asn.org ?? "unknown network"}, AS${o.asn.asn}${ghNote}`
    : o.githubActions ? NOT_DEPLOY_KEY : null;
  const where = [place ? `in ${place}` : null, net ? `(${net})` : null].filter(Boolean).join(" ");
  return `From ${o.ip}${where ? ` ${where}` : ""}, NOT one of your servers`;
}

/** The source address of a detection: the column, else the evidence, else "from <ip>" in the log line. */
export function detectionSourceIp(sourceIp: string | null | undefined, evidence?: Record<string, unknown> | null): string | null {
  const candidates: unknown[] = [sourceIp, evidence?.source_ip, evidence?.ip];
  const line = typeof evidence?.message === "string" ? evidence.message : "";
  const m = line.match(/\bfrom\s+\[?([0-9a-fA-F:.]+?)\]?(?:\s|$|,|;)/);
  if (m) candidates.push(m[1]);
  for (const c of candidates) {
    const v = typeof c === "string" ? c.trim() : "";
    if (v && isIP(v) !== 0) return v;
  }
  return null;
}

/** Address -> the org's own machine name, from its servers and its inventory. */
export async function ownAddresses(admin: SupabaseClient, orgId: string): Promise<Map<string, string>> {
  const own = new Map<string, string>();
  const add = (ip: unknown, name: unknown) => {
    const v = typeof ip === "string" ? ip.trim() : "";
    const n = typeof name === "string" ? name.trim() : "";
    if (v && n && isIP(v) !== 0 && !own.has(v)) own.set(v, n);
  };
  try {
    type Row = { name?: string; hostname?: string; ip_address?: string; public_ip?: string };
    const first = await admin.from("servers").select("name, hostname, ip_address, public_ip").eq("org_id", orgId);
    let rows = (first.data ?? []) as Row[];
    // public_ip is a hand-applied migration: work without it.
    if (first.error && /public_ip/.test(first.error.message)) {
      const second = await admin.from("servers").select("name, hostname, ip_address").eq("org_id", orgId);
      rows = (second.data ?? []) as Row[];
    }
    for (const s of rows) {
      const name = s.name || s.hostname;
      add(s.public_ip, name);
      add(s.ip_address, name);
    }
  } catch (err) {
    console.error("[incidents] origin: servers lookup failed:", (err as Error).message);
  }
  try {
    const { data } = await admin.from("fleet_inventories").select("document").eq("org_id", orgId).maybeSingle();
    const doc = (data as { document?: unknown } | null)?.document;
    if (doc && typeof doc === "object") {
      for (const d of parseInventory(doc as object).devices) {
        if (d.status === "retired") continue;
        for (const ip of [...(d.addresses?.ipv4 ?? []), ...(d.addresses?.ipv6 ?? [])]) add(ip, d.name);
      }
    }
  } catch (err) {
    console.error("[incidents] origin: inventory lookup failed:", (err as Error).message);
  }
  return own;
}

/** The facts behind one address's origin line, so a caller can add the login's key. */
export type AddressFacts = OriginFacts & { label: string };

/** Each address for one org, with its facts. Lookups wait a few seconds at most on a cold start. */
export async function describeOriginsDetailed(admin: SupabaseClient, orgId: string, ips: string[]): Promise<Map<string, AddressFacts>> {
  const out = new Map<string, AddressFacts>();
  const unique = [...new Set(ips.filter((ip) => isIP(ip) !== 0))];
  if (unique.length === 0) return out;
  const own = await ownAddresses(admin, orgId);
  const outside = unique.filter((ip) => !own.has(ip) && isPublicIp(ip));
  let geo = new Map<string, GeoHit>();
  try {
    geo = outside.length ? await lookupIps(outside, 4000) : geo;
  } catch {
    // no city database: say less
  }
  const isRunner = outside.length ? await githubActionsChecker().catch(() => () => false) : () => false;
  for (const ip of unique) {
    let asn: AsnHit | null = null;
    if (outside.includes(ip)) asn = await lookupAsn(ip, 3000).catch(() => null);
    const facts: OriginFacts = { ip, own: own.get(ip) ?? null, geo: geo.get(ip) ?? null, asn, githubActions: outside.includes(ip) && isRunner(ip) };
    out.set(ip, { ...facts, label: describeOrigin(facts) });
  }
  return out;
}

/** Describe each address for one org. Lookups wait a few seconds at most on a cold start. */
export async function describeOrigins(admin: SupabaseClient, orgId: string, ips: string[]): Promise<Map<string, string>> {
  const detailed = await describeOriginsDetailed(admin, orgId, ips);
  return new Map([...detailed].map(([ip, o]) => [ip, o.label]));
}

/** The deploy key's comment from a login's evidence, when the daemon marked the key automation. */
export function deployKeyOf(evidence?: Record<string, unknown> | null): string | null {
  if (evidence?.key_kind !== "automation") return null;
  const c = typeof evidence.key_comment === "string" ? evidence.key_comment.trim() : "";
  return c || null;
}

/** Whether an origin line marks known automation (never paged). */
export function isKnownAutomationOrigin(origin: string | null): boolean {
  return !!origin && origin.endsWith(KNOWN_AUTOMATION);
}
