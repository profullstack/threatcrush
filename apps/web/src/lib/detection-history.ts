import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { fingerprintOf, type EventLike } from "@threatcrush/event-detail";
import { detectionUsername } from "@/lib/detection-display";
import { findSecret } from "@/lib/incidents/secret-guard";
import { deployKeyOf, describeOrigin, describeOriginsDetailed, detectionSourceIp } from "@/lib/incidents/origin";

/**
 * One detection and its history: every detection sharing its source address
 * or SSH key fingerprint anywhere in the org (an intruder moves between
 * hosts), plus the same host's recent detections and the same rule on that
 * host. Feeds the detail view shared by the dashboard and the desktop app
 * (@threatcrush/event-detail), so both show the same timeline.
 *
 * Bounded: 30 days, 100 rows per relation, only servers the caller can see.
 * A row whose metadata trips the secret guard (an old agent's bug) has its
 * metadata replaced rather than returned.
 */

export class HistoryError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const COLUMNS = "id, server_id, rule_id, severity, title, description, source_ip, username, raw_metadata, detected_at, last_detected_at, occurrences, status";
const WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const PER_RELATION = 100;

export interface DetectionRow {
  id: string;
  server_id: string | null;
  rule_id: string | null;
  severity: string;
  title: string;
  description: string | null;
  source_ip: string | null;
  username: string | null;
  raw_metadata: Record<string, unknown> | null;
  detected_at: string;
  last_detected_at: string | null;
  occurrences: number | null;
  status: string;
}

export type HistoryEvent = EventLike & { server_name: string | null };

function safe(row: DetectionRow): DetectionRow {
  const hit = findSecret(row.raw_metadata ?? {}, "raw_metadata");
  const out = { ...row, username: detectionUsername(row) };
  return hit ? { ...out, raw_metadata: { _redacted: `secret material (${hit.kind}) removed` } } : out;
}

/** A detection row in the shape the shared detail view reads. */
export function toEventLike(row: DetectionRow, serverName: string | null): HistoryEvent {
  return {
    id: row.id,
    at: row.detected_at,
    severity: row.severity,
    title: row.title,
    description: row.description,
    rule_id: row.rule_id,
    source_ip: row.source_ip,
    username: row.username,
    server_id: row.server_id,
    host: serverName,
    server_name: serverName,
    metadata: row.raw_metadata,
    status: row.status,
    occurrences: row.occurrences,
  };
}

export async function detectionHistory(admin: SupabaseClient, orgId: string, detectionId: string, visible: string[] | null) {
  if (!UUID.test(detectionId)) throw new HistoryError("Invalid detection id", 400);
  let q = admin.from("detections").select(COLUMNS).eq("organization_id", orgId).eq("id", detectionId);
  if (visible) q = q.in("server_id", visible.length ? visible : ["00000000-0000-0000-0000-000000000000"]);
  const { data: found, error } = await q.maybeSingle();
  if (error) throw new Error(`detection: ${error.message}`);
  if (!found) throw new HistoryError("Detection not found", 404);
  const row = safe(found as DetectionRow);

  const evidence = row.raw_metadata && typeof row.raw_metadata.evidence === "object" && row.raw_metadata.evidence !== null
    ? row.raw_metadata.evidence as Record<string, unknown>
    : null;
  const ip = detectionSourceIp(row.source_ip, evidence);
  const fp = fingerprintOf(toEventLike(row, null));
  const since = new Date(Date.parse(row.detected_at) - WINDOW_MS).toISOString();

  const base = () => {
    let x = admin.from("detections").select(COLUMNS).eq("organization_id", orgId).gte("detected_at", since)
      .order("detected_at", { ascending: false }).limit(PER_RELATION);
    if (visible) x = x.in("server_id", visible);
    return x;
  };
  const queries: Array<PromiseLike<{ data: unknown; error: { message: string } | null }>> = [];
  if (ip) queries.push(base().eq("source_ip", ip));
  if (fp) {
    queries.push(base().eq("raw_metadata->evidence->ssh_context->key->>fingerprint", fp));
    queries.push(base().eq("raw_metadata->evidence->>fingerprint", fp));
  }
  if (row.server_id) {
    queries.push(base().eq("server_id", row.server_id));
    if (row.rule_id) queries.push(base().eq("server_id", row.server_id).eq("rule_id", row.rule_id));
  }

  const [results, servers, origins, incident] = await Promise.all([
    Promise.all(queries),
    admin.from("servers").select("id, name, hostname").eq("org_id", orgId),
    ip ? describeOriginsDetailed(admin, orgId, [ip]).catch(() => new Map()) : Promise.resolve(new Map()),
    row.severity === "critical" && row.server_id
      ? admin.from("incidents").select("id, status, assignee_id").eq("org_id", orgId)
        .eq("dedupe_key", `detection:${row.server_id}:${row.rule_id || row.title}`.slice(0, 200))
        .order("last_seen_at", { ascending: false }).limit(1).maybeSingle()
      : Promise.resolve({ data: null }),
  ]);

  const names = new Map<string, string>();
  for (const s of (servers.data ?? []) as Array<{ id: string; name: string | null; hostname: string | null }>) {
    names.set(s.id, s.name || s.hostname || s.id.slice(0, 8));
  }
  const related = new Map<string, HistoryEvent>();
  for (const r of results) {
    if (r.error) {
      // A JSON-path filter on an old schema should not take the view down.
      console.error("[detections] history relation:", r.error.message);
      continue;
    }
    for (const d of (r.data ?? []) as DetectionRow[]) {
      if (d.id === row.id || related.has(d.id)) continue;
      related.set(d.id, toEventLike(safe(d), d.server_id ? names.get(d.server_id) ?? null : null));
    }
  }

  const facts = ip ? origins.get(ip) : undefined;
  const deployKey = deployKeyOf(evidence);
  const originLabel = facts ? describeOrigin({ ...facts, deployKey }) : null;

  return {
    detection: toEventLike(row, row.server_id ? names.get(row.server_id) ?? null : null),
    related: [...related.values()],
    origin: originLabel,
    incident: (incident as { data: { id: string; status: string; assignee_id: string | null } | null }).data ?? null,
    window_days: WINDOW_MS / 86_400_000,
  };
}
