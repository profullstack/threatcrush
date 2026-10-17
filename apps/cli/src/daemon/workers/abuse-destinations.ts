import type { AbuseEvidence } from './abuse-evidence.js';
import { abuseipdbCategories } from './abuse-evidence.js';

/**
 * The outbound side of the abuse-reporter: the public statements, and how they
 * are kept clean. Everything here is best-effort and off the ban path — a
 * destination being slow or down must never slow detection.
 */

export type DestinationName = 'abuseipdb' | 'stopforumspam';

export interface DestinationResult {
  destination: DestinationName;
  ok: boolean;
  /** Short machine note: an id, a confidence score, or the error. */
  detail: string;
}

export interface ReportPayload {
  ip: string;
  evidence: AbuseEvidence;
  /** The redacted, human-readable comment. Already safe to publish. */
  comment: string;
  /** AbuseIPDB numeric categories. */
  categories: number[];
}

export interface DestinationKeys {
  abuseipdb?: string;
  stopforumspam?: string;
}

/** Nothing leaves without a 15s ceiling, like every other outbound call here. */
const TIMEOUT_MS = 15_000;

/**
 * R8: build the comment ourselves from the shape of the evidence, never from
 * the raw detector messages. Those carry our own hostnames, request paths and
 * sometimes a username — none of which belongs in a public accusation. What
 * leaves the host is a count, a timeframe and a category, and nothing else.
 */
export function buildComment(evidence: AbuseEvidence): string {
  const hours = Math.max(1, Math.round((evidence.lastSeen - evidence.firstSeen) / 3_600_000));
  const kinds = evidence.categories
    .map((c) => ({ auth: 'authentication', web: 'web-application', scan: 'scanning', network: 'network', pentest: 'exploitation' }[c] ?? c))
    .join(', ');
  return (
    `Automated report from ThreatCrush. ${evidence.total} malicious ${kinds || 'attack'} ` +
    `event(s) observed from this address across ${evidence.signals} detector(s) over ~${hours}h, ` +
    `confirmed by a completed TCP handshake. Blocked by automated defence. ` +
    `No reply expected.`
  );
}

/** Assemble the full redacted payload for a source that has cleared the bar. */
export function buildPayload(ip: string, evidence: AbuseEvidence): ReportPayload {
  return { ip, evidence, comment: buildComment(evidence), categories: abuseipdbCategories(evidence) };
}

/**
 * Report to AbuseIPDB (PRD 0015 R6). POST /api/v2/report, key in the header,
 * categories as a CSV. A 429 is their daily cap, not an error on our side.
 */
export async function reportToAbuseIPDB(payload: ReportPayload, apiKey: string): Promise<DestinationResult> {
  const body = new URLSearchParams({
    ip: payload.ip,
    categories: payload.categories.join(','),
    comment: payload.comment.slice(0, 1024),
  });
  try {
    const res = await fetch('https://api.abuseipdb.com/api/v2/report', {
      method: 'POST',
      headers: {
        Key: apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status === 429) {
      return { destination: 'abuseipdb', ok: false, detail: 'rate-limited by AbuseIPDB (daily cap)' };
    }
    const json = (await res.json().catch(() => ({}))) as {
      data?: { abuseConfidenceScore?: number };
      errors?: Array<{ detail?: string }>;
    };
    if (!res.ok) {
      const detail = json.errors?.map((e) => e.detail).filter(Boolean).join('; ') || `HTTP ${res.status}`;
      return { destination: 'abuseipdb', ok: false, detail };
    }
    const score = json.data?.abuseConfidenceScore;
    return { destination: 'abuseipdb', ok: true, detail: score !== undefined ? `confidence ${score}` : 'reported' };
  } catch (err) {
    return { destination: 'abuseipdb', ok: false, detail: (err as Error).message };
  }
}

/**
 * Report to StopForumSpam (PRD 0015 R7). SFS is a forum/signup-spam database:
 * add.php requires `username`, `email` and `ip_addr` together (plus our
 * `api_key`; `evidence` is optional). Those must be what the spammer actually
 * submitted, so only a source whose evidence carries a form-spam identity is
 * sent here — an SSH scanner has no username or email and is skipped, never
 * padded with made-up ones. SFS answers 200 with an empty body on success and
 * 403 with the reason in a <p> on refusal.
 */
export async function reportToStopForumSpam(payload: ReportPayload, apiKey: string): Promise<DestinationResult> {
  const identity = payload.evidence.formSpam;
  if (!identity) {
    return { destination: 'stopforumspam', ok: false, detail: 'skipped: no form-spam username/email in evidence' };
  }
  const body = new URLSearchParams({
    username: identity.username,
    email: identity.email,
    ip_addr: payload.ip,
    evidence: payload.comment.slice(0, 1000),
    api_key: apiKey,
  });
  try {
    const res = await fetch('https://www.stopforumspam.com/add.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await res.text().catch(() => '');
    if (res.status === 200) return { destination: 'stopforumspam', ok: true, detail: 'reported' };
    const reason = /<p[^>]*>([\s\S]*?)<\/p>/i.exec(text)?.[1]?.replace(/<[^>]+>/g, '').trim();
    return { destination: 'stopforumspam', ok: false, detail: `HTTP ${res.status} ${(reason || text).slice(0, 160)}`.trim() };
  } catch (err) {
    return { destination: 'stopforumspam', ok: false, detail: (err as Error).message };
  }
}

/** Dispatch one payload to each configured destination that has a key. */
export async function dispatch(
  payload: ReportPayload,
  destinations: DestinationName[],
  keys: DestinationKeys,
): Promise<DestinationResult[]> {
  const jobs: Array<Promise<DestinationResult>> = [];
  for (const dest of destinations) {
    if (dest === 'abuseipdb' && keys.abuseipdb) jobs.push(reportToAbuseIPDB(payload, keys.abuseipdb));
    // SFS only takes forum/signup spam with a real username + email; skip silently otherwise.
    else if (dest === 'stopforumspam' && keys.stopforumspam && payload.evidence.formSpam) jobs.push(reportToStopForumSpam(payload, keys.stopforumspam));
  }
  return Promise.all(jobs);
}
