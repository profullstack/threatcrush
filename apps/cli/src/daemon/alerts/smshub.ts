import { hostname } from 'node:os';
import type { ThreatEvent } from '../../types/events.js';

/**
 * `[alerts.smshub]`: page a phone straight from the daemon through smshub's
 * alert API (POST /api/v1/alerts; it texts when it can and calls for
 * critical). Normally the dashboard pages on-call for critical detections;
 * this is the path that still works when the box cannot reach the dashboard
 * (2026-10-28: a Supabase key rotation logged every daemon out for hours).
 *
 *   [alerts.smshub]
 *   enabled = true
 *   api_key = "smshub_..."        # or api_key_env = "SMSHUB_ALERT_API_KEY"
 *   to = "+15551234567"           # optional; default is the account's alert phone
 *   min_severity = "critical"     # default
 *   fallback_only = true          # default: only while the dashboard link is down
 */
export interface SmshubConfig {
  api_key?: string;
  api_key_env?: string;
  url?: string;
  to?: string;
  min_severity?: 'low' | 'medium' | 'high' | 'critical';
  fallback_only?: boolean;
}

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const DEDUPE_MS = 10 * 60_000;
const MAX_PER_HOUR = 6;

export function smshubText(event: ThreatEvent, host = hostname()): string {
  const evidence = (event.details?.evidence as { message?: string } | undefined)?.message;
  const text = `ThreatCrush ${event.severity.toUpperCase()} on ${host}: ${event.message}${evidence && !event.message.includes(evidence) ? ` | ${evidence}` : ''}`;
  return text.replace(/\s+/g, ' ').slice(0, 600);
}

export function smshubChannel(
  config: SmshubConfig,
  opts: { cloudHealthy?: () => boolean; fetchImpl?: typeof fetch; now?: () => number; log?: (line: string) => void } = {},
): (event: ThreatEvent) => Promise<void> {
  const sent = new Map<string, number>();
  const recent: number[] = [];
  const now = opts.now ?? Date.now;
  const doFetch = opts.fetchImpl ?? fetch;
  return async (event) => {
    const key = config.api_key || (config.api_key_env ? process.env[config.api_key_env] : undefined) || process.env.SMSHUB_ALERT_API_KEY;
    if (!key) return;
    if ((SEVERITY_RANK[event.severity] ?? 0) < (SEVERITY_RANK[config.min_severity ?? 'critical'] ?? 4)) return;
    if (config.fallback_only !== false && opts.cloudHealthy?.()) return;
    const message = smshubText(event);
    const at = now();
    const dedupe = `${event.details?.rule_id ?? event.module}|${event.source_ip ?? ''}|${event.details?.fingerprint ?? ''}`;
    if (at - (sent.get(dedupe) ?? 0) < DEDUPE_MS) return;
    while (recent.length && recent[0] < at - 3_600_000) recent.shift();
    if (recent.length >= MAX_PER_HOUR) return;
    sent.set(dedupe, at);
    recent.push(at);
    const base = (config.url || 'https://smshub.dev').replace(/\/$/, '');
    try {
      const res = await doFetch(`${base}/api/v1/alerts`, {
        method: 'POST',
        headers: { 'X-API-Key': key, 'Content-Type': 'application/json', 'User-Agent': 'threatcrush-daemon' },
        body: JSON.stringify({ message, severity: event.severity === 'critical' ? 'critical' : 'warning', ...(config.to ? { to: config.to } : {}) }),
        signal: AbortSignal.timeout(15_000),
      });
      opts.log?.(`[alerts] smshub ${res.ok ? 'paged' : `failed HTTP ${res.status}`}: ${message.slice(0, 160)}`);
    } catch (err) {
      opts.log?.(`[alerts] smshub failed: ${(err as Error).message}`);
    }
  };
}
