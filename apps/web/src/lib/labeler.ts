import type { SupabaseClient } from "@supabase/supabase-js";
import { scanBytes, type AvDetection, type AvFileResult, type HashReputation } from "@threatcrush/av";
import type { KeyObject } from "node:crypto";
import { lookupReputations } from "@/lib/av-reputation";
import { isoSeconds, LABELER_DID, signLabel, type Label, type LabelValue } from "@/lib/labeler-sign";
import { nichedbDomain, parseIndicator } from "@/lib/reputation-service";

/**
 * The ThreatCrush labeler (c0mpute DIP-0036). Turns CrushAV verdicts and
 * domain reputation into signed labels on files (`sha256:<hex>`).
 *
 * Precision over recall: only detections with impact `malicious` become a
 * label. A label refuses someone's site on every gateway that subscribes, so
 * a false positive is worse than a miss.
 */

export const LIMITS = {
  maxFiles: 500,
  maxFileBytes: 5 * 1024 * 1024,
  maxTotalBytes: 20 * 1024 * 1024,
  maxPathLength: 512,
  maxDomainsPerScan: 25,
  maxQueryUris: 500,
} as const;

const DAY = 86_400_000;
const TTL: Record<"heuristic" | "signature" | "reputation" | "domain", number> = {
  heuristic: 30 * DAY,
  signature: 90 * DAY,
  reputation: 30 * DAY,
  domain: 7 * DAY,
};
/** Re-issue a stored label when it has less than this left, so callers can cache what they get. */
const REISSUE_MARGIN = 7 * DAY;

const MINER_IDS = new Set(["CrushAV.PUA.CoinMiner", "CrushAV.Web.BrowserMiner"]);
const PHISH_IDS = new Set([
  "CrushAV.Web.PhishKitExfil",
  "CrushAV.Web.ClickFix",
  "CrushAV.macOS.PasswordPhishStealer",
]);

/** The label a malicious detection maps to; null for anything that must not label. */
export function labelValueFor(d: AvDetection): LabelValue | null {
  if (d.impact !== "malicious") return null;
  // The EICAR test file proves the pipeline end to end; label it like malware so operators can test refusal.
  if (MINER_IDS.has(d.id)) return "cryptominer";
  if (PHISH_IDS.has(d.id)) return "phishing";
  return "malware";
}

export interface ScanFile {
  path: string;
  bytes: Uint8Array;
}

export interface Finding {
  uri: string;
  val: LabelValue;
  ttl: number;
  evidence: string;
  path: string;
}

/**
 * Hosts a file actively uses: form posts, scripts, frames, fetch/XHR/beacon
 * targets and redirects. Plain links and prose that merely name a domain are
 * ignored on purpose (a security blog listing bad domains is not phishing).
 */
export function activeHosts(text: string): string[] {
  const out = new Set<string>();
  const URL_RE = String.raw`["'\x60]\s*((?:https?:)?\/\/[^"'\x60\s<>]{3,300})`;
  const patterns = [
    new RegExp(String.raw`<form\b[^>]*\baction\s*=\s*` + URL_RE, "gi"),
    new RegExp(String.raw`<(?:script|iframe|frame|embed)\b[^>]*\bsrc\s*=\s*` + URL_RE, "gi"),
    new RegExp(String.raw`\b(?:fetch|sendBeacon|\.open\s*\(\s*["'\x60](?:POST|GET|PUT)["'\x60]\s*,)\s*\(?\s*` + URL_RE, "gi"),
    new RegExp(String.raw`(?:location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\()\s*` + URL_RE, "gi"),
    new RegExp(String.raw`<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*((?:https?:)?\/\/[^"'\s>]{3,300})`, "gi"),
  ];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) {
      const raw = m[1].startsWith("//") ? `https:${m[1]}` : m[1];
      const ind = parseIndicator(raw);
      if (ind?.type === "domain") out.add(ind.value);
      if (out.size >= LIMITS.maxDomainsPerScan) return [...out];
    }
  }
  return [...out];
}

const isTexty = (r: AvFileResult) => r.kind === "text" || r.kind === "script" || r.kind === "unknown";

export interface ScanDeps {
  reputations?: (hashes: string[]) => Promise<Map<string, HashReputation>>;
  domain?: typeof nichedbDomain;
}

/** Scan files with CrushAV + hash reputation + active-domain reputation. Pure apart from deps. */
export async function scanFiles(files: ScanFile[], deps: ScanDeps = {}): Promise<{ results: AvFileResult[]; findings: Finding[] }> {
  const reputations = deps.reputations ?? ((h: string[]) => lookupReputations(h));
  const domainCheck = deps.domain ?? nichedbDomain;
  const results = await Promise.all(files.map((f) => scanBytes({ name: f.path, bytes: f.bytes })));
  const findings: Finding[] = [];
  const add = (f: Finding) => {
    if (!findings.some((x) => x.uri === f.uri && x.val === f.val)) findings.push(f);
  };

  for (const r of results) {
    if (!r.sha256) continue;
    for (const d of r.detections) {
      const val = labelValueFor(d);
      if (val) add({ uri: `sha256:${r.sha256}`, val, ttl: d.engine === "signature" ? TTL.signature : TTL.heuristic, evidence: `crushav:${d.id}`, path: r.path });
    }
  }

  const hashes = [...new Set(results.map((r) => r.sha256).filter((h): h is string => Boolean(h)))];
  const reps = hashes.length ? await reputations(hashes).catch(() => new Map<string, HashReputation>()) : new Map<string, HashReputation>();
  for (const r of results) {
    const rep = r.sha256 ? reps.get(r.sha256) : undefined;
    if (rep?.knownMalicious) {
      add({ uri: `sha256:${r.sha256}`, val: "malware", ttl: TTL.reputation, evidence: `reputation:${rep.knownMalicious}${rep.malwareName ? `:${rep.malwareName}` : ""}`.slice(0, 300), path: r.path });
    }
  }

  // Domains the site actively uses, checked once each across all files.
  const byHost = new Map<string, AvFileResult[]>();
  files.forEach((f, i) => {
    const r = results[i];
    if (!r.sha256 || !isTexty(r) || f.bytes.length > LIMITS.maxFileBytes) return;
    for (const h of activeHosts(Buffer.from(f.bytes).toString("latin1"))) {
      if (!byHost.has(h) && byHost.size >= LIMITS.maxDomainsPerScan) continue;
      byHost.set(h, [...(byHost.get(h) ?? []), r]);
    }
  });
  const hosts = [...byHost.keys()];
  const reports = await Promise.all(hosts.map((h) => domainCheck(h).catch(() => null)));
  hosts.forEach((host, i) => {
    const rep = reports[i];
    if (!rep?.listed) return;
    const why = rep.reasons.join(" ").toLowerCase();
    const val: LabelValue = /phish/.test(why) ? "phishing" : "malware";
    for (const r of byHost.get(host) ?? []) {
      add({ uri: `sha256:${r.sha256}`, val, ttl: TTL.domain, evidence: `domain:${host}`, path: r.path });
    }
  });

  return { results, findings };
}

// ---------- storage: an append-only public log in labeler_labels ----------

interface Row {
  id: number;
  src: string;
  uri: string;
  val: LabelValue;
  neg: boolean;
  cts: string;
  exp: string;
  evidence: string | null;
  sig: string;
}

const rowToLabel = (r: Row): Label => {
  const l: Label = { kind: "label", ver: 1, src: r.src, uri: r.uri, val: r.val, neg: r.neg, cts: isoSeconds(Date.parse(r.cts)), exp: isoSeconds(Date.parse(r.exp)), sig: r.sig };
  if (r.evidence) l.evidence = r.evidence;
  return l;
};

/**
 * The labels currently in force for these subjects: newest record per
 * (uri, val) wins, so a later `neg` retracts and a later positive re-applies.
 * Expired positives are dropped.
 */
export async function currentLabels(admin: SupabaseClient, uris: string[], now = Date.now()): Promise<Label[]> {
  if (uris.length === 0) return [];
  const { data, error } = await admin
    .from("labeler_labels")
    .select("id,src,uri,val,neg,cts,exp,evidence,sig")
    .in("uri", uris)
    .order("id", { ascending: false })
    .limit(5000);
  if (error) throw new Error(`labeler_labels read failed: ${error.message}`);
  const seen = new Set<string>();
  const out: Label[] = [];
  for (const r of (data ?? []) as Row[]) {
    const k = `${r.uri}\n${r.val}`;
    if (seen.has(k)) continue;
    seen.add(k);
    if (!r.neg && Date.parse(r.exp) > now) out.push(rowToLabel(r));
  }
  return out;
}

/** Turn findings into signed, stored labels, reusing a stored one with enough life left. */
export async function issueLabels(admin: SupabaseClient, key: KeyObject, findings: Finding[], now = Date.now()): Promise<Label[]> {
  if (findings.length === 0) return [];
  const existing = await currentLabels(admin, [...new Set(findings.map((f) => f.uri))], now);
  const out: Label[] = [];
  const fresh: Label[] = [];
  for (const f of findings) {
    const have = existing.find((l) => l.uri === f.uri && l.val === f.val);
    if (have && Date.parse(have.exp) - now > REISSUE_MARGIN) {
      out.push(have);
      continue;
    }
    const l = signLabel({ src: LABELER_DID, uri: f.uri, val: f.val, neg: false, cts: isoSeconds(now), exp: isoSeconds(now + f.ttl), evidence: f.evidence }, key);
    fresh.push(l);
    out.push(l);
  }
  if (fresh.length) await insertLabels(admin, fresh);
  return out;
}

export async function insertLabels(admin: SupabaseClient, labels: Label[]): Promise<void> {
  const { error } = await admin.from("labeler_labels").insert(
    labels.map((l) => ({ src: l.src, uri: l.uri, val: l.val, neg: l.neg, cts: l.cts, exp: l.exp, evidence: l.evidence ?? null, sig: l.sig })),
  );
  if (error) throw new Error(`labeler_labels insert failed: ${error.message}`);
}

/** The public log, oldest first, after a cursor. */
export async function readLog(admin: SupabaseClient, after: number, limit: number): Promise<{ labels: Array<Label & { id: number }>; next: number | null }> {
  const { data, error } = await admin
    .from("labeler_labels")
    .select("id,src,uri,val,neg,cts,exp,evidence,sig")
    .gt("id", after)
    .order("id", { ascending: true })
    .limit(limit);
  if (error) throw new Error(`labeler_labels read failed: ${error.message}`);
  const rows = (data ?? []) as Row[];
  return { labels: rows.map((r) => ({ ...rowToLabel(r), id: r.id })), next: rows.length === limit ? rows[rows.length - 1].id : null };
}
