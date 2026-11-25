/**
 * VirusTotal enrichment (free public API) for IP and domain reputation.
 *
 * A second opinion alongside the ThreatCrush community feed and nichedb. Needs a
 * free VirusTotal API key in VIRUSTOTAL_API_KEY; without it, enrichment is
 * silently skipped (every function returns null), so nothing depends on it.
 * Read at request time — Next.js inlines process.env.NAME at build.
 */

export interface VtVerdict {
  /** Engines flagging this indicator as malicious. */
  malicious: number;
  suspicious: number;
  harmless: number;
  /** VT community reputation score (can be negative). */
  reputation: number | null;
  /** Convenience: malicious + suspicious > 0. */
  listed: boolean;
  source: "virustotal";
  permalink: string;
}

export function virusTotalKey(): string {
  const name = "VIRUSTOTAL_API_KEY";
  return process.env[name] ?? "";
}

export function vtEnabled(): boolean {
  return virusTotalKey().length > 0;
}

interface VtStats { malicious?: number; suspicious?: number; harmless?: number }

async function vtGet(path: string, permalink: string, fetchImpl: typeof fetch): Promise<VtVerdict | null> {
  const key = virusTotalKey();
  if (!key) return null;
  try {
    const res = await fetchImpl(`https://www.virustotal.com/api/v3/${path}`, {
      headers: { "x-apikey": key },
      signal: AbortSignal.timeout(5000),
    });
    if (res.status !== 200) return null;
    const j = (await res.json()) as { data?: { attributes?: { last_analysis_stats?: VtStats; reputation?: number } } };
    const attr = j.data?.attributes;
    if (!attr) return null;
    const s = attr.last_analysis_stats ?? {};
    const malicious = s.malicious ?? 0;
    const suspicious = s.suspicious ?? 0;
    return {
      malicious,
      suspicious,
      harmless: s.harmless ?? 0,
      reputation: typeof attr.reputation === "number" ? attr.reputation : null,
      listed: malicious + suspicious > 0,
      source: "virustotal",
      permalink,
    };
  } catch {
    return null;
  }
}

export function vtIp(ip: string, fetchImpl: typeof fetch = fetch): Promise<VtVerdict | null> {
  return vtGet(`ip_addresses/${encodeURIComponent(ip)}`, `https://www.virustotal.com/gui/ip-address/${ip}`, fetchImpl);
}

export function vtDomain(domain: string, fetchImpl: typeof fetch = fetch): Promise<VtVerdict | null> {
  return vtGet(`domains/${encodeURIComponent(domain)}`, `https://www.virustotal.com/gui/domain/${domain}`, fetchImpl);
}
