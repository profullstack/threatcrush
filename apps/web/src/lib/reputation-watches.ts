import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { deliverAlert, webhookAlert } from "./alerts/senders";
import { emitToOrg } from "./webhooks/hub";
import type { AlertDestinationRow, AlertMessage } from "./alerts/types";
import { tierFor } from "./reputation";
import { lookupIndicator, type AnyReport, type Indicator } from "./reputation-service";

/**
 * Reputation Pro watch lists: an org names addresses and domains it cares
 * about (its own mail servers, its domains, a vendor's IPs), and an hourly
 * job looks each one up and alerts through the org's alert destinations when
 * it is listed, cleared, or its score jumps while listed.
 */

export const MAX_WATCHES_PER_ORG = 100;
/** A listed indicator whose score moves this much alerts again. */
export const SCORE_JUMP = 20;

export interface WatchRow {
  id: string;
  org_id: string;
  indicator: string;
  kind: "ip" | "domain";
  destination_id: string | null;
  note: string | null;
  last_listed: boolean | null;
  last_score: number | null;
}

export type WatchChange = "listed" | "cleared" | "score" | null;

/** What changed since the last check. A first check alerts only when the indicator is listed. */
export function watchChange(prev: Pick<WatchRow, "last_listed" | "last_score">, now: { listed: boolean; score: number }): WatchChange {
  if (prev.last_listed == null) return now.listed ? "listed" : null;
  if (!prev.last_listed && now.listed) return "listed";
  if (prev.last_listed && !now.listed) return "cleared";
  if (now.listed && Math.abs(now.score - (prev.last_score ?? 0)) >= SCORE_JUMP) return "score";
  return null;
}

const reasonsOf = (r: AnyReport): string[] => (r.type === "domain" ? r.reasons : (r.pro?.reasons ?? []));

export function watchMessage(watch: WatchRow, report: AnyReport, change: Exclude<WatchChange, null>, orgSlug: string | null): AlertMessage {
  const what = watch.kind === "domain" ? "Domain" : "Address";
  const verb = change === "listed" ? "is now listed" : change === "cleared" ? "is no longer listed" : `score moved to ${report.score}`;
  const reasons = reasonsOf(report).slice(0, 5);
  const base = process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";
  return {
    title: `${what} ${watch.indicator} ${verb}`,
    body: [
      `ThreatCrush reputation: ${watch.indicator} ${verb} (score ${report.score}/100).`,
      ...(watch.note ? [`Watch note: ${watch.note}`] : []),
      ...reasons.map((r) => `- ${r}`),
      `Public record: ${report.public_record}`,
    ].join("\n"),
    severity: change === "cleared" ? "info" : report.score >= 70 ? "high" : "medium",
    url: orgSlug ? `${base}/org/${orgSlug}` : `${base}/reputation`,
    timestamp: new Date().toISOString(),
    tag: `reputation-${watch.indicator}`,
    reputation: { watch_id: watch.id, indicator: watch.indicator, kind: watch.kind, change, score: report.score, listed: report.listed },
  };
}

/**
 * Check the watches due next (oldest check first), alert on changes, record
 * the result. Orgs without a running Pro period are skipped and their
 * watches stay as they were. Returns counts for the cron log.
 */
export async function runWatches(
  admin: SupabaseClient,
  { limit = 200, lookup = lookupIndicator }: { limit?: number; lookup?: typeof lookupIndicator } = {},
): Promise<{ checked: number; alerts: number; skipped: number; failed: number }> {
  const { data, error } = await admin
    .from("reputation_watches")
    .select("id, org_id, indicator, kind, destination_id, note, last_listed, last_score")
    .order("last_checked_at", { ascending: true, nullsFirst: true })
    .limit(limit);
  if (error) throw new Error(`watches: ${error.message}`);
  const watches = (data ?? []) as WatchRow[];
  const out = { checked: 0, alerts: 0, skipped: 0, failed: 0 };
  const proByOrg = new Map<string, boolean>();
  const destsByOrg = new Map<string, AlertDestinationRow[]>();
  const slugByOrg = new Map<string, string | null>();

  for (const w of watches) {
    if (!proByOrg.has(w.org_id)) proByOrg.set(w.org_id, (await tierFor(admin, w.org_id)) === "pro");
    if (!proByOrg.get(w.org_id)) {
      out.skipped++;
      continue;
    }
    let report: AnyReport;
    try {
      report = await lookup(admin, { type: w.kind, value: w.indicator } as Indicator, "pro");
    } catch {
      out.failed++;
      continue;
    }
    // A domain answer without nichedb's half is not a verdict: leave the watch as it was
    // rather than send a "cleared" that is only a timeout.
    if (report.type === "domain" && !report.complete) {
      out.failed++;
      continue;
    }
    out.checked++;
    const now = new Date().toISOString();
    const change = watchChange(w, report);
    await admin
      .from("reputation_watches")
      .update({
        last_listed: report.listed,
        last_score: report.score,
        last_reasons: reasonsOf(report).slice(0, 10),
        last_checked_at: now,
        ...(change ? { last_changed_at: now } : {}),
      })
      .eq("id", w.id);
    if (!change) continue;

    if (!destsByOrg.has(w.org_id)) {
      const [{ data: dests }, { data: org }] = await Promise.all([
        admin.from("alert_destinations").select("id, organization_id, name, type, config, enabled").eq("organization_id", w.org_id).eq("enabled", true),
        admin.from("organizations").select("slug").eq("id", w.org_id).maybeSingle(),
      ]);
      destsByOrg.set(w.org_id, (dests ?? []) as AlertDestinationRow[]);
      slugByOrg.set(w.org_id, (org as { slug?: string } | null)?.slug ?? null);
    }
    const all = destsByOrg.get(w.org_id) ?? [];
    const targets = w.destination_id ? all.filter((d) => d.id === w.destination_id) : all;
    const message = watchMessage(w, report, change, slugByOrg.get(w.org_id) ?? null);
    for (const d of targets) {
      const result = await deliverAlert(d, message);
      if (result.ok) out.alerts++;
      else console.error(`[reputation] watch alert to ${d.id} failed: ${result.error}`);
    }
    // Webhook endpoints made via /api/v1/webhooks see every watch change in the org.
    const hub = webhookAlert(message);
    if (hub && !w.destination_id) out.alerts += await emitToOrg(w.org_id, [hub]);
  }
  return out;
}
