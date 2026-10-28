import "server-only";
import { getSupabaseAdmin } from "@/lib/supabase";
import { notifyIncident } from "./notify";
import { pageable, raiseDetectionIncidents, type CriticalDetection } from "./store";

/** After ingest: critical detections -> incidents -> one page per new incident. Never throws. */
export async function pageCriticalDetections(
  detections: CriticalDetection[],
  servers: Map<string, { fleet_id: string | null; name: string | null }>,
): Promise<void> {
  try {
    const admin = getSupabaseAdmin();
    const outcomes = await raiseDetectionIncidents(admin, detections, servers);
    const paged = new Set<string>();
    for (const o of outcomes) {
      if (!o.page || paged.has(o.incident.id)) continue;
      paged.add(o.incident.id);
      await notifyIncident(pageable(o.incident), admin);
    }
  } catch (err) {
    console.error("[incidents] critical detection paging failed:", (err as Error).message);
  }
}
