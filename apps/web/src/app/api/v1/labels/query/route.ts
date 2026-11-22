import { NextResponse, type NextRequest } from "next/server";
import { LOOKUP_BATCH } from "@threatcrush/av";
import { getAdminClient } from "@/lib/api-auth";
import { lookupReputations } from "@/lib/av-reputation";
import { currentLabels, issueLabels, type Finding } from "@/lib/labeler";
import { NO_STORE, parseQueryUris, readJsonCapped } from "@/lib/labeler-http";
import { labelerKey } from "@/lib/labeler-sign";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS });
}

/**
 * POST /api/v1/labels/query {uris: ["sha256:<hex>", ...]}   (public, rate limited)
 * -> {labels: Label[]}  the labels in force for these subjects right now.
 *
 * Gateways call this to re-check files they already serve: a hash that turned
 * up on MalwareBazaar since it was published gets a fresh label here, and a
 * retracted (`neg`) label disappears. Only the first LOOKUP_BATCH subjects get
 * a live reputation check per call; the stored log covers the rest.
 */
export async function POST(req: NextRequest) {
  const headers = { ...CORS, ...NO_STORE };
  const read = await readJsonCapped(req, 64 * 1024);
  if (!read.ok) return NextResponse.json({ error: read.error }, { status: read.status, headers });
  const parsed = parseQueryUris(read.body);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: parsed.status, headers });

  const admin = getAdminClient();
  try {
    const key = labelerKey();
    if (key) {
      const hashes = parsed.uris.slice(0, LOOKUP_BATCH).map((u) => u.slice("sha256:".length));
      const reps = await lookupReputations(hashes).catch(() => new Map());
      const findings: Finding[] = [];
      for (const [h, rep] of reps) {
        if (rep.knownMalicious) {
          findings.push({ uri: `sha256:${h}`, val: "malware", ttl: 30 * 86_400_000, evidence: `reputation:${rep.knownMalicious}${rep.malwareName ? `:${rep.malwareName}` : ""}`.slice(0, 300), path: "" });
        }
      }
      if (findings.length) await issueLabels(admin, key, findings);
    }
    return NextResponse.json({ labels: await currentLabels(admin, parsed.uris) }, { headers });
  } catch (e) {
    console.error("[labeler] query failed", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Label store unavailable; try again" }, { status: 503, headers });
  }
}
