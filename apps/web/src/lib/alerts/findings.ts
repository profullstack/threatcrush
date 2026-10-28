import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { getSupabaseAdmin } from "@/lib/supabase";
import { emitToOrg } from "@/lib/webhooks/hub";
import { COUNTED_STATUSES, outcomeRow } from "./dispatch";
import { deliverAlert, webhookAlert } from "./senders";
import { SEVERITY_RANK, type AlertDestinationRow, type AlertMessage, type AlertRuleRow, type FindingAlertPayload, type Severity } from "./types";

/**
 * Alerts for tracked scan / pentest / ai-scan findings. Same rules, channels
 * and hourly limits as detections (Settings -> Alerts): a rule fires when a
 * run raised a new or reopened finding at or above its min_severity. A rule
 * scoped to particular servers is about servers, so only org-wide rules (no
 * server_scope) apply. One alert per run and destination lists everything
 * that run raised, so a first scan of a big repo is one message, not 200.
 */

const DEFAULT_RATE_LIMIT_PER_HOUR = 60;
const HOUR_MS = 60 * 60 * 1000;
const LISTED = 10;
const SOURCE_LABEL = { scan: "code scan", pentest: "pentest", "ai-scan": "AI red-team scan" } as const;

const appUrl = () => (process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com").replace(/\/$/, "");
const rank = (s: string) => SEVERITY_RANK[s as Severity] ?? -1;

export function buildFindingsMessage(p: FindingAlertPayload, orgSlug: string | null, now = new Date()): AlertMessage {
  const sorted = [...p.findings].sort((a, b) => rank(b.severity) - rank(a.severity));
  const top = sorted[0].severity;
  const reopened = sorted.filter((f) => f.reopened).length;
  const counts = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => [s, sorted.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");
  const lines = sorted.slice(0, LISTED).map((f) => `• [${f.severity.toUpperCase()}]${f.reopened ? " (back after a fix)" : ""} ${f.message}${f.location && f.location !== p.property.target ? ` — ${f.location}` : ""}`);
  if (sorted.length > LISTED) lines.push(`…and ${sorted.length - LISTED} more`);
  const n = sorted.length;
  return {
    title: `[${top.toUpperCase()}] ${n} new finding${n === 1 ? "" : "s"} in ${p.property.name}`,
    body: [`${counts} from a ${SOURCE_LABEL[p.source]}${reopened ? ` (${reopened} reopened)` : ""}.`, ...lines].join("\n"),
    severity: top,
    url: orgSlug ? `${appUrl()}/org/${encodeURIComponent(orgSlug)}/findings` : `${appUrl()}/dashboard`,
    timestamp: now.toISOString(),
    tag: `findings-${p.run_id}`,
    findings: p,
  };
}

/** Never throws: called after the response, like detection alerts. */
export async function dispatchFindingAlerts(p: FindingAlertPayload, admin: SupabaseClient = getSupabaseAdmin()): Promise<{ sent: number }> {
  const out = { sent: 0 };
  try {
    if (!p.findings.length) return out;
    const [rulesRes, destsRes, orgRes] = await Promise.all([
      admin.from("alert_rules")
        .select("id, organization_id, name, min_severity, server_scope, destination_id, rate_limit_per_hour, enabled")
        .eq("organization_id", p.organization_id).eq("enabled", true).order("created_at", { ascending: true }),
      admin.from("alert_destinations").select("id, organization_id, name, type, config, enabled")
        .eq("organization_id", p.organization_id).eq("enabled", true),
      admin.from("organizations").select("slug").eq("id", p.organization_id).maybeSingle(),
    ]);
    if (rulesRes.error || destsRes.error) {
      console.error("[alerts] findings: could not load rules/destinations:", rulesRes.error ?? destsRes.error);
      return out;
    }
    const dests = new Map(((destsRes.data ?? []) as AlertDestinationRow[]).map((d) => [d.id, d]));
    const top = Math.max(...p.findings.map((f) => rank(f.severity)));
    const firing = ((rulesRes.data ?? []) as AlertRuleRow[]).filter((r) => {
      const d = dests.get(r.destination_id);
      const scoped = Array.isArray(r.server_scope) && r.server_scope.length > 0;
      return r.enabled && d?.enabled && d.organization_id === p.organization_id && !scoped && rank(r.min_severity) >= 0 && top >= rank(r.min_severity);
    });
    const orgSlug = (orgRes.data as { slug?: string } | null)?.slug ?? null;
    // Webhook endpoints made via /api/v1/webhooks get every run's new findings.
    const hub = webhookAlert(buildFindingsMessage(p, orgSlug));
    await emitToOrg(p.organization_id, hub ? [hub] : []);
    if (!firing.length) return out;

        const since = new Date(Date.now() - HOUR_MS).toISOString();
    const deliveredTo = new Set<string>();
    const rows: Array<Record<string, unknown>> = [];
    for (const rule of firing) {
      const dest = dests.get(rule.destination_id)!;
      if (deliveredTo.has(dest.id)) continue;
      // Each rule only lists what clears its own threshold.
      const mine = { ...p, findings: p.findings.filter((f) => rank(f.severity) >= rank(rule.min_severity)) };
      const base = { organization_id: p.organization_id, rule_id: rule.id, destination_id: dest.id, detection_id: null };
      const { count } = await admin.from("alert_deliveries").select("id", { count: "exact", head: true })
        .eq("rule_id", rule.id).in("status", COUNTED_STATUSES).gte("created_at", since);
      const limit = rule.rate_limit_per_hour ?? DEFAULT_RATE_LIMIT_PER_HOUR;
      if ((count ?? 0) >= limit) {
        rows.push({ ...base, status: "rate_limited", error: `Rule limit of ${limit} alerts per hour reached` });
        continue;
      }
      deliveredTo.add(dest.id);
      const outcome = await deliverAlert(dest, buildFindingsMessage(mine, orgSlug));
      if (outcome.ok) out.sent++;
      rows.push(outcomeRow(base, outcome));
    }
    if (rows.length) {
      const { error } = await admin.from("alert_deliveries").insert(rows);
      if (error) console.error("[alerts] findings: could not record deliveries:", error.message);
    }
  } catch (e) {
    console.error("[alerts] findings dispatch failed:", (e as Error).message);
  }
  return out;
}
