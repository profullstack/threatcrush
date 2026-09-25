import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import {
  INGEST_MAX_BODY_BYTES,
  INGEST_MAX_EVENTS,
  parseIngestEvent,
  readBodyCapped,
  type DetectionEvent,
  type HardeningFindingEvent,
  type HeartbeatEvent,
  type IngestEvent,
  type RemediationEvent,
} from "@/lib/ingest-events";
import { getSupabaseAdmin } from "@/lib/supabase";

type Rejection = { index: number; error: string };

/** One row returned by the ingest_detections RPC, per distinct dedupe group. */
type IngestedDetection = {
  id: string;
  organization_id: string;
  server_id: string;
  severity: string;
  title: string;
  description: string | null;
  source_ip: string | null;
  rule_id: string | null;
  detected_at: string;
  occurrences: number;
  inserted: boolean;
};

function badRequest(error: string) {
  return NextResponse.json({ error }, { status: 400 });
}

// POST /api/ingest — the daemon pushes heartbeats, detections, hardening
// findings and its own remediation results in batches (contract v2; v1
// heartbeat/detection bodies are the same shape and still accepted).
export async function POST(req: NextRequest) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const text = await readBodyCapped(req, INGEST_MAX_BODY_BYTES);
    if (text === null) return badRequest(`Body exceeds ${INGEST_MAX_BODY_BYTES} bytes`);

    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return badRequest("Body must be JSON");
    }
    const events = (body as { events?: unknown } | null)?.events;
    if (!Array.isArray(events) || events.length === 0) {
      return badRequest("events array is required");
    }
    if (events.length > INGEST_MAX_EVENTS) {
      return badRequest(`Max ${INGEST_MAX_EVENTS} events per batch`);
    }

    const now = new Date().toISOString();
    const rejected: Rejection[] = [];
    const valid: Array<{ index: number; event: IngestEvent }> = [];
    events.forEach((raw, index) => {
      const parsed = parseIngestEvent(raw, now);
      if (parsed.ok) valid.push({ index, event: parsed.event });
      else rejected.push({ index, error: parsed.error });
    });

    // Resolve access once per distinct server: server → org, then the caller's
    // memberships among those orgs. Unknown servers and servers in orgs the
    // caller doesn't belong to get the same answer, so ids can't be probed.
    const admin = getSupabaseAdmin();
    const serverIds = [...new Set(valid.map((v) => v.event.server_id))];
    const serverOrg = new Map<string, string>();
    if (serverIds.length > 0) {
      const { data: servers, error: serversError } = await admin
        .from("servers")
        .select("id, org_id")
        .in("id", serverIds);
      if (serversError) throw new Error(`servers lookup: ${serversError.message}`);

      const orgIds = [...new Set((servers ?? []).map((s: { org_id: string }) => s.org_id))];
      const memberOf = new Set<string>();
      if (orgIds.length > 0) {
        const { data: memberships, error: membersError } = await admin
          .from("organization_members")
          .select("org_id")
          .eq("user_id", auth.userId)
          .in("org_id", orgIds);
        if (membersError) throw new Error(`membership lookup: ${membersError.message}`);
        for (const m of memberships ?? []) memberOf.add((m as { org_id: string }).org_id);
      }
      for (const s of (servers ?? []) as Array<{ id: string; org_id: string }>) {
        if (memberOf.has(s.org_id)) serverOrg.set(s.id, s.org_id);
      }
    }

    const heartbeats = new Map<string, HeartbeatEvent>();
    let heartbeatCount = 0;
    const detections: Array<DetectionEvent & { organization_id: string; ord: number }> = [];
    const findings: Array<HardeningFindingEvent & { organization_id: string; ord: number }> = [];
    const remediations: Array<RemediationEvent & { organization_id: string }> = [];

    for (const { index, event } of valid) {
      const orgId = serverOrg.get(event.server_id);
      if (!orgId) {
        rejected.push({ index, error: `no access to server ${event.server_id}` });
        continue;
      }
      switch (event.type) {
        case "heartbeat": {
          // Several heartbeats for one server collapse into one update; the
          // latest non-empty version/hostname wins.
          const prev = heartbeats.get(event.server_id);
          heartbeats.set(event.server_id, {
            ...event,
            version: event.version ?? prev?.version ?? null,
            hostname: event.hostname ?? prev?.hostname ?? null,
          });
          heartbeatCount++;
          break;
        }
        case "detection":
          detections.push({ ...event, organization_id: orgId, ord: index });
          break;
        case "hardening_finding":
          findings.push({ ...event, organization_id: orgId, ord: index });
          break;
        case "remediation":
          remediations.push({ ...event, organization_id: orgId });
          break;
      }
    }
    rejected.sort((a, b) => a.index - b.index);

    // Order matters for retries after a 5xx: heartbeats, detections (deduped)
    // and findings (upserted) are idempotent; remediations are only idempotent
    // when the daemon sends event_id, so they are written last.
    await Promise.all(
      [...heartbeats.values()].map(async (hb) => {
        const updates: Record<string, unknown> = { last_seen: now, status: "online" };
        if (hb.version) updates.threatcrushd_version = hb.version;
        if (hb.hostname) updates.hostname = hb.hostname;
        const { error } = await admin.from("servers").update(updates).eq("id", hb.server_id);
        if (error) throw new Error(`heartbeat: ${error.message}`);
      }),
    );

    let newDetections: IngestedDetection[] = [];
    if (detections.length > 0) {
      const rows = detections.map(({ type: _type, ...row }) => row);
      const { data, error } = await admin.rpc("ingest_detections", { p_rows: rows });
      if (error) throw new Error(`detections: ${error.message}`);
      newDetections = ((data ?? []) as IngestedDetection[]).filter((d) => d.inserted);
    }

    let findingCount = 0;
    if (findings.length > 0) {
      const rows = findings.map(({ type: _type, ...row }) => row);
      const { error } = await admin.rpc("ingest_hardening_findings", { p_rows: rows });
      if (error) throw new Error(`findings: ${error.message}`);
      findingCount = findings.length;
    }

    // A replayed remediation (same event_id) inserts nothing and counts as
    // deduplicated; events from daemons that don't send event_id always insert.
    let remediationCount = 0;
    if (remediations.length > 0) {
      const { data, error } = await admin.rpc("ingest_remediations", {
        p_rows: remediations.map((r) => ({
          organization_id: r.organization_id,
          server_id: r.server_id,
          action_type: r.action_type,
          target_value: r.target_value,
          status: r.status,
          executed_at: r.executed_at,
          expires_at: r.expires_at,
          metadata: {
            source: "daemon",
            rule_id: r.rule_id,
            reason: r.reason,
            error: r.error,
            dry_run: r.dry_run,
            event_id: r.event_id,
          },
        })),
      });
      if (error) throw new Error(`remediations: ${error.message}`);
      remediationCount = typeof data === "number" ? data : 0;
    }

    return NextResponse.json({
      success: true,
      accepted: {
        detections: newDetections.length,
        deduplicated: detections.length - newDetections.length + remediations.length - remediationCount,
        heartbeats: heartbeatCount,
        findings: findingCount,
        remediations: remediationCount,
      },
      rejected,
    });
  } catch (err) {
    console.error("Ingest API error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
