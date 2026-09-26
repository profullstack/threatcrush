import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { getSupabaseAdmin } from "@/lib/supabase";
import { buildDetectionMessage } from "./message";
import { ruleMatches } from "./rules";
import { deliverAlert } from "./senders";
import type { AlertableDetection, AlertDestinationRow, AlertRuleRow } from "./types";

export type { AlertableDetection } from "./types";

/** Column default for alert_rules.rate_limit_per_hour. */
const DEFAULT_RATE_LIMIT_PER_HOUR = 60;
const HOUR_MS = 60 * 60 * 1000;

interface DeliveryRow {
  organization_id: string;
  rule_id: string;
  destination_id: string;
  detection_id: string;
  status: "sent" | "failed" | "rate_limited";
  error: string | null;
}

/**
 * Evaluate the org's enabled alert rules against newly inserted detections and
 * deliver to each matching destination. Every attempt — sent, failed or
 * skipped by the rule's hourly rate limit — is recorded in alert_deliveries.
 *
 * Runs after the ingest response (via `after()`), so it never throws: a
 * broken destination or a missing provider key becomes a `failed` row.
 */
export async function dispatchDetectionAlerts(detections: AlertableDetection[]): Promise<void> {
  if (!Array.isArray(detections) || detections.length === 0) return;

  const byOrg = new Map<string, AlertableDetection[]>();
  for (const detection of detections) {
    const list = byOrg.get(detection.organization_id) ?? [];
    list.push(detection);
    byOrg.set(detection.organization_id, list);
  }

  let admin: SupabaseClient;
  try {
    admin = getSupabaseAdmin();
  } catch (err) {
    console.error("[alerts] dispatch skipped:", (err as Error).message);
    return;
  }

  for (const [orgId, orgDetections] of byOrg) {
    try {
      await dispatchForOrg(admin, orgId, orgDetections);
    } catch (err) {
      console.error(`[alerts] dispatch failed for org ${orgId}:`, err);
    }
  }
}

async function dispatchForOrg(admin: SupabaseClient, orgId: string, detections: AlertableDetection[]) {
  const [rulesRes, destinationsRes] = await Promise.all([
    admin
      .from("alert_rules")
      .select("id, organization_id, name, min_severity, server_scope, destination_id, rate_limit_per_hour, enabled")
      .eq("organization_id", orgId)
      .eq("enabled", true)
      .order("created_at", { ascending: true }),
    admin
      .from("alert_destinations")
      .select("id, organization_id, name, type, config, enabled")
      .eq("organization_id", orgId)
      .eq("enabled", true),
  ]);
  if (rulesRes.error || destinationsRes.error) {
    console.error("[alerts] could not load rules/destinations:", rulesRes.error ?? destinationsRes.error);
    return;
  }

  const rules = (rulesRes.data ?? []) as AlertRuleRow[];
  const destinations = new Map(
    ((destinationsRes.data ?? []) as AlertDestinationRow[]).map((dest) => [dest.id, dest]),
  );
  const firing = rules.filter((rule) =>
    detections.some((detection) => ruleMatches(rule, destinations.get(rule.destination_id), detection)),
  );
  if (firing.length === 0) return;

  const serverIds = [...new Set(detections.map((detection) => detection.server_id))];
  const since = new Date(Date.now() - HOUR_MS).toISOString();
  const [orgRes, serversRes, usageCounts] = await Promise.all([
    admin.from("organizations").select("slug").eq("id", orgId).maybeSingle(),
    admin.from("servers").select("id, name, hostname").in("id", serverIds),
    Promise.all(
      firing.map(async (rule) => {
        // Attempts (sent or failed) in the last hour count against the limit;
        // rate_limited rows do not.
        const { count, error } = await admin
          .from("alert_deliveries")
          .select("id", { count: "exact", head: true })
          .eq("rule_id", rule.id)
          .in("status", ["sent", "failed"])
          .gte("created_at", since);
        if (error) console.error(`[alerts] rate-limit count failed for rule ${rule.id}:`, error.message);
        return [rule.id, count ?? 0] as const;
      }),
    ),
  ]);

  const orgSlug = (orgRes.data as { slug?: string } | null)?.slug ?? null;
  const serverNames = new Map(
    ((serversRes.data ?? []) as { id: string; name: string | null; hostname: string | null }[]).map(
      (server) => [server.id, server.name || server.hostname || null],
    ),
  );
  const used = new Map(usageCounts);

  for (const detection of detections) {
    const message = buildDetectionMessage(detection, {
      orgSlug,
      serverName: serverNames.get(detection.server_id) ?? null,
    });
    const rows: DeliveryRow[] = [];
    // Two rules routing to the same destination send one alert, not two.
    const deliveredTo = new Set<string>();
    const sends: Promise<void>[] = [];

    for (const rule of firing) {
      const destination = destinations.get(rule.destination_id);
      if (!destination || !ruleMatches(rule, destination, detection)) continue;
      if (deliveredTo.has(destination.id)) continue;

      const base = {
        organization_id: orgId,
        rule_id: rule.id,
        destination_id: destination.id,
        detection_id: detection.id,
      };
      const limit = rule.rate_limit_per_hour ?? DEFAULT_RATE_LIMIT_PER_HOUR;
      const attempts = used.get(rule.id) ?? 0;
      if (attempts >= limit) {
        rows.push({ ...base, status: "rate_limited", error: `Rule limit of ${limit} alerts per hour reached` });
        continue;
      }

      used.set(rule.id, attempts + 1);
      deliveredTo.add(destination.id);
      sends.push(
        deliverAlert(destination, message).then((outcome) => {
          rows.push(
            outcome.ok
              ? { ...base, status: "sent", error: outcome.detail ?? null }
              : { ...base, status: "failed", error: outcome.error.slice(0, 1000) },
          );
        }),
      );
    }

    await Promise.all(sends);
    if (rows.length === 0) continue;
    const { error } = await admin.from("alert_deliveries").insert(rows);
    if (error) console.error("[alerts] could not record deliveries:", error.message);
  }
}
