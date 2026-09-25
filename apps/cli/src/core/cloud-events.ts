import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { readCliConfig, hasSession } from './cli-config.js';
import type { EventSeverity, ThreatEvent } from '../types/events.js';
import type { HardeningResult } from '../commands/harden.js';

/** The `POST /api/ingest` event shapes (cloud contract v1). */
export type IngestEvent =
  | { type: 'heartbeat'; server_id: string; version?: string; hostname?: string }
  | {
      type: 'detection'; server_id: string; severity: EventSeverity; title: string;
      rule_id?: string; description?: string; source_ip?: string; username?: string;
      raw_metadata?: Record<string, unknown>; detected_at?: string;
    }
  | {
      type: 'hardening_finding'; server_id: string; finding_key: string;
      status: 'pass' | 'warn' | 'fail'; severity: EventSeverity; title: string;
      recommendation?: string; observed_at?: string;
    }
  | {
      type: 'remediation'; server_id: string; action_type: 'block' | 'unblock';
      /** Minted once, when the event is created, and spooled with it: the server dedupes replays on it. */
      event_id: string;
      target_value: string; status: 'executed' | 'failed'; rule_id?: string;
      reason?: string; error?: string; dry_run?: boolean;
      executed_at?: string; expires_at?: string | null;
    };

export interface IngestResponse {
  success?: boolean;
  accepted?: Partial<Record<'detections' | 'deduplicated' | 'heartbeats' | 'findings' | 'remediations', number>>;
  rejected?: Array<{ index: number; error: string }>;
}

export interface CloudLink {
  serverId: string;
  orgId: string;
}

/** The server this machine reports as, or null when not logged in or not linked. */
export function currentLink(): CloudLink | null {
  if (!hasSession()) return null;
  const cfg = readCliConfig();
  if (!cfg.server_id || !cfg.server_org_id) return null;
  return { serverId: cfg.server_id, orgId: cfg.server_org_id };
}

export const SEVERITY_RANK: Record<EventSeverity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

export const MAX_TITLE_CHARS = 300;
export const MAX_METADATA_BYTES = 16 * 1024;
const MAX_STRING_CHARS = 1024;

function jsonBytes(value: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(value) ?? '');
  } catch {
    return Infinity;
  }
}

/**
 * Keep event metadata under the ingest limit. Long strings (a whole request
 * line, a module's dump) are cut first; if that is not enough the largest keys
 * go, and `_truncated` says so. Never throws: unserialisable values (cycles,
 * BigInt) are dropped rather than taking the upload down with them.
 */
export function trimMetadata(meta: Record<string, unknown>): Record<string, unknown> {
  const entries: Array<[string, unknown]> = [];
  for (const [key, value] of Object.entries(meta)) {
    if (value === undefined || typeof value === 'function') continue;
    const cut = typeof value === 'string' && value.length > MAX_STRING_CHARS
      ? `${value.slice(0, MAX_STRING_CHARS)}…`
      : value;
    if (jsonBytes(cut) === Infinity) continue;
    entries.push([key, cut]);
  }

  let out = Object.fromEntries(entries);
  let truncated = entries.length !== Object.keys(meta).length;
  if (jsonBytes(out) > MAX_METADATA_BYTES) {
    truncated = true;
    const bySize = [...entries].sort((a, b) => jsonBytes(a[1]) - jsonBytes(b[1]));
    while (bySize.length > 0 && jsonBytes({ ...Object.fromEntries(bySize), _truncated: true }) > MAX_METADATA_BYTES) {
      bySize.pop();
    }
    out = Object.fromEntries(bySize);
  }
  return truncated ? { ...out, _truncated: true } : out;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined;
}

/**
 * A bus event as an ingest `detection`. Rule-engine detections carry their rule
 * id; an event from a module no rule covers is reported under the module's
 * name, which is also what the server deduplicates on.
 */
export function detectionEvent(serverId: string, event: ThreatEvent): IngestEvent {
  const { rule_id, username, user, description, ...rest } = event.details ?? {};
  const title = event.module === 'rule-engine'
    ? event.message.replace(/^\[DETECTION\]\s*/, '')
    : event.message;
  return {
    type: 'detection',
    server_id: serverId,
    severity: event.severity,
    title: title.slice(0, MAX_TITLE_CHARS) || event.module,
    rule_id: str(rule_id) ?? event.module,
    description: str(description),
    source_ip: event.source_ip && isIP(event.source_ip) ? event.source_ip : undefined,
    username: str(username) ?? str(user),
    raw_metadata: trimMetadata({ module: event.module, category: event.category, ...rest }),
    detected_at: event.timestamp.toISOString(),
  };
}

/**
 * A `firewall-rules` bus event as an ingest `remediation`, or null when the
 * event is not a ban/unban (or the dashboard asked for it, in which case the
 * row already exists and gets its result through the PATCH instead).
 */
export function remediationEvent(serverId: string, event: ThreatEvent): IngestEvent | null {
  const d = event.details ?? {};
  if (d.action !== 'block' && d.action !== 'unblock') return null;
  if (d.origin === 'cloud' || !event.source_ip) return null;
  const at = event.timestamp;
  const ttl = typeof d.ttl_seconds === 'number' ? d.ttl_seconds : null;
  return {
    type: 'remediation',
    server_id: serverId,
    event_id: randomUUID(),
    action_type: d.action,
    target_value: event.source_ip,
    status: d.failed === true ? 'failed' : 'executed',
    rule_id: str(d.rule_id),
    reason: str(d.reason),
    error: str(d.error),
    dry_run: d.dry_run === true,
    executed_at: at.toISOString(),
    expires_at: d.action === 'block' && ttl !== null && d.failed !== true
      ? new Date(at.getTime() + ttl * 1000).toISOString()
      : null,
  };
}

export function findingEvents(serverId: string, results: HardeningResult[], observedAt = new Date()): IngestEvent[] {
  return results.map((r) => ({
    type: 'hardening_finding',
    server_id: serverId,
    finding_key: r.key,
    status: r.status,
    severity: r.severity,
    title: r.title.slice(0, MAX_TITLE_CHARS),
    recommendation: r.recommendation,
    observed_at: observedAt.toISOString(),
  }));
}
