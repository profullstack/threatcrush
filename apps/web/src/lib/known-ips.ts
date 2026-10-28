import { isIP } from "node:net";
import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Known IPs: an org's allowlist entries (type ip / cidr) with a label, read as
 * "these addresses are ours". Daemons never ban them; alerts and the Known
 * IPs page call out attack traffic from them, since one of our own addresses
 * running exploits means a compromised service (the choke point).
 */

export interface KnownIp {
  id: string;
  type: "ip" | "cidr";
  value: string;
  label: string | null;
  note: string | null;
  source: "manual" | "server";
  server_id: string | null;
}

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);
}

function v6ToBigInt(ip: string): bigint {
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const parts = ip.includes("::") ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  return parts.reduce((n, p) => n * BigInt(65536) + BigInt(parseInt(p || "0", 16)), BigInt(0));
}

/** Whether `ip` equals an ip entry or falls inside a cidr entry. */
export function inKnown(ip: string, entry: Pick<KnownIp, "type" | "value">): boolean {
  const fam = isIP(ip);
  if (!fam) return false;
  if (entry.type === "ip") return entry.value === ip;
  const [net, bitsRaw] = entry.value.split("/");
  const bits = Number(bitsRaw);
  if (isIP(net) !== fam || !Number.isInteger(bits)) return false;
  if (fam === 4) {
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
    return ((v4ToInt(ip) & mask) >>> 0) === ((v4ToInt(net) & mask) >>> 0);
  }
  const div = BigInt(2) ** BigInt(128 - bits);
  return v6ToBigInt(ip) / div === v6ToBigInt(net) / div;
}

/** The most specific known entry an address matches: an exact ip beats a range. */
export function matchKnown(ip: string | null | undefined, entries: KnownIp[]): KnownIp | null {
  if (!ip) return null;
  const hits = entries.filter((e) => inKnown(ip, e));
  return hits.find((e) => e.type === "ip") ?? hits[0] ?? null;
}

export function knownName(e: KnownIp): string {
  return e.label || e.note || e.value;
}

/** Never throws: a lookup problem means no "ours" label, never a lost alert. */
export async function loadKnownIps(admin: SupabaseClient, orgId: string): Promise<KnownIp[]> {
  try {
    return await readKnownIps(admin, orgId);
  } catch {
    return [];
  }
}

async function readKnownIps(admin: SupabaseClient, orgId: string): Promise<KnownIp[]> {
  const { data, error } = await admin
    .from("allowlists")
    .select("id, type, value, label, note, source, server_id")
    .eq("organization_id", orgId)
    .in("type", ["ip", "cidr"]);
  if (error) {
    // Before the known-IPs migration the extra columns do not exist; fall back.
    const { data: basic } = await admin.from("allowlists").select("id, type, value, note").eq("organization_id", orgId).in("type", ["ip", "cidr"]);
    return ((basic ?? []) as KnownIp[]).map((e) => ({ ...e, label: null, source: "manual", server_id: null }));
  }
  return (data ?? []) as KnownIp[];
}
