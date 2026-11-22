import { NextResponse, type NextRequest } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getAdminClient } from "@/lib/api-auth";
import { currentLabels, insertLabels } from "@/lib/labeler";
import { NO_STORE, readJsonCapped } from "@/lib/labeler-http";
import { isoSeconds, LABEL_VALUES, LABELER_DID, labelerKey, SHA256_URI, signLabel, type LabelValue } from "@/lib/labeler-sign";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/v1/labels/negate {uri, val, reason}   (ThreatCrush admins only)
 *
 * Grants an appeal: appends a signed `neg` record, which retracts the label on
 * every subscriber at its next query. The original label stays in the log.
 * A negation lasts a year; a later scan finding the same thing issues a new
 * positive label, which wins because it is newer.
 */
export async function POST(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;
  const key = labelerKey();
  if (!key) return NextResponse.json({ error: "Labeler signing key is not configured" }, { status: 503, headers: NO_STORE });

  const read = await readJsonCapped(req, 4096);
  if (!read.ok) return NextResponse.json({ error: read.error }, { status: read.status, headers: NO_STORE });
  const b = read.body as { uri?: unknown; val?: unknown; reason?: unknown } | null;
  const uri = typeof b?.uri === "string" ? b.uri.trim().toLowerCase() : "";
  const val = b?.val as LabelValue;
  const reason = typeof b?.reason === "string" ? b.reason.replace(/[^\x20-\x7e]/g, "").trim().slice(0, 200) : "";
  if (!SHA256_URI.test(uri) || !LABEL_VALUES.includes(val) || !reason) {
    return NextResponse.json({ error: "uri (sha256:<hex>), val and reason are required" }, { status: 400, headers: NO_STORE });
  }
  const admin = getAdminClient();
  const active = await currentLabels(admin, [uri]);
  if (!active.some((l) => l.val === val)) return NextResponse.json({ error: "No label in force for that uri and val" }, { status: 404, headers: NO_STORE });
  const now = Date.now();
  const neg = signLabel({ src: LABELER_DID, uri, val, neg: true, cts: isoSeconds(now), exp: isoSeconds(now + 365 * 86_400_000), evidence: `appeal:${guard.id.slice(0, 8)}:${reason}` }, key);
  await insertLabels(admin, [neg]);
  return NextResponse.json({ label: neg }, { headers: NO_STORE });
}
