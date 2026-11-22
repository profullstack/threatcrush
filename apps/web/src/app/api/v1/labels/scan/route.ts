import { NextResponse, type NextRequest } from "next/server";
import { getAdminClient } from "@/lib/api-auth";
import { issueLabels, LIMITS, scanFiles } from "@/lib/labeler";
import { NO_STORE, parseScanFiles, readJsonCapped, scanAuthorized } from "@/lib/labeler-http";
import { labelerKey } from "@/lib/labeler-sign";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

// base64 is 4/3 of the bytes, plus JSON framing for up to maxFiles entries.
const MAX_BODY = Math.ceil((LIMITS.maxTotalBytes * 4) / 3) + LIMITS.maxFiles * 1024;

/**
 * POST /api/v1/labels/scan  {files:[{path, content_b64}]}   (Bearer token)
 * -> {labels: Label[], files: [{path, sha256, verdict, labels:[val]}]}
 *
 * Scans a site's files with CrushAV, hash reputation and the reputation of
 * domains the files actively use, and returns signed labels (DIP-0036) for
 * every file with a malicious finding. Labels are stored in the public log.
 * File contents are never stored.
 */
export async function POST(req: NextRequest) {
  if (!scanAuthorized(req)) return NextResponse.json({ error: "A labeler scan token is required" }, { status: 401, headers: NO_STORE });
  const key = labelerKey();
  if (!key) return NextResponse.json({ error: "Labeler signing key is not configured" }, { status: 503, headers: NO_STORE });

  const read = await readJsonCapped(req, MAX_BODY);
  if (!read.ok) return NextResponse.json({ error: read.error }, { status: read.status, headers: NO_STORE });
  const parsed = parseScanFiles(read.body);
  if ("error" in parsed) return NextResponse.json({ error: parsed.error }, { status: parsed.status, headers: NO_STORE });

  const { results, findings } = await scanFiles(parsed.files);
  let labels;
  try {
    labels = await issueLabels(getAdminClient(), key, findings);
  } catch (e) {
    console.error("[labeler] issue failed", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Could not record labels; try again" }, { status: 503, headers: NO_STORE });
  }
  const files = results.map((r) => ({
    path: r.path,
    sha256: r.sha256,
    verdict: r.verdict,
    labels: [...new Set(labels.filter((l) => l.uri === `sha256:${r.sha256}`).map((l) => l.val))],
    detections: r.detections.filter((d) => d.impact !== "info").map((d) => ({ id: d.id, name: d.name, impact: d.impact })),
  }));
  return NextResponse.json({ labels, files }, { headers: NO_STORE });
}
