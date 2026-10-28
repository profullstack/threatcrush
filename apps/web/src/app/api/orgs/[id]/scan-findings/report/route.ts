import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { atLeast, findingsRoleOf, getPrincipal } from "@/lib/access";
import { isFindingSource, normalizeFindings, syncRunFindings, urlSafe } from "@/lib/scan-findings";

// POST /api/orgs/[id]/scan-findings/report — the CLI's one-shot upload after a
// local `threatcrush scan` / `pentest` / `ai-scan`. Finds (or creates) the
// property for the target, records a finished property_run, and folds its
// findings into scan_findings.
//
// { source: "scan"|"pentest"|"ai-scan", target, kind?, name?, scope?,
//   result: { findings, severity_summary?, summary?, error? }, output?, worker_id? }

const KINDS = ["url", "api", "domain", "ip", "repo"] as const;
const DEFAULT_KIND: Record<string, (typeof KINDS)[number]> = { scan: "repo", pentest: "url", "ai-scan": "api" };
const MAX_BODY = 4 * 1024 * 1024;

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId } = await params;
  if (!atLeast(await findingsRoleOf(admin, p, orgId), "write")) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

  const text = await req.text();
  if (text.length > MAX_BODY) return NextResponse.json({ error: "Report too large" }, { status: 413 });
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(text);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const source = body.source;
  if (!isFindingSource(source)) return NextResponse.json({ error: "source must be scan, pentest or ai-scan" }, { status: 400 });
  const target = typeof body.target === "string" ? urlSafe(body.target.trim().slice(0, 1000)) : "";
  if (!target) return NextResponse.json({ error: "target required" }, { status: 400 });
  const kind = KINDS.includes(body.kind as (typeof KINDS)[number]) ? (body.kind as (typeof KINDS)[number]) : DEFAULT_KIND[source];
  const scope = typeof body.scope === "string" ? body.scope.slice(0, 500) : "";
  const result = (body.result && typeof body.result === "object" ? body.result : {}) as Record<string, unknown>;
  const findings = normalizeFindings(result.findings);
  const userId = p.kind === "user" ? p.userId : null;

  // One property per (org, kind, target).
  let { data: property } = await admin
    .from("properties").select("id, name").eq("org_id", orgId).eq("kind", kind).eq("target", target).maybeSingle();
  if (!property) {
    const name = (typeof body.name === "string" && body.name.trim()) || target;
    const { data: created, error } = await admin
      .from("properties")
      .insert({ org_id: orgId, name: name.slice(0, 200), kind, target, created_by: userId })
      .select("id, name")
      .single();
    if (error || !created) return NextResponse.json({ error: "Failed to create property" }, { status: 500 });
    property = created;
  }

  const now = new Date().toISOString();
  const status = typeof result.error === "string" && result.error ? "failed" : "succeeded";
  const { data: run, error: runErr } = await admin
    .from("property_runs")
    .insert({
      org_id: orgId, property_id: property.id, type: source, scope, status, trigger: "cli",
      source: "local", worker_id: typeof body.worker_id === "string" ? body.worker_id.slice(0, 200) : null,
      started_at: now, completed_at: now, findings_count: findings.length,
      severity_summary: result.severity_summary && typeof result.severity_summary === "object" ? result.severity_summary : null,
      summary: typeof result.summary === "string" ? result.summary.slice(0, 2000) : null,
      output: typeof body.output === "string" ? body.output.slice(0, 200_000) : null,
      findings, error: status === "failed" ? String(result.error).slice(0, 2000) : null, created_by: userId,
    })
    .select("id, org_id, property_id, type, scope, status, findings")
    .single();
  if (runErr || !run) return NextResponse.json({ error: "Failed to record run" }, { status: 500 });
  await admin.from("properties").update({ last_run_at: now, last_run_status: status }).eq("id", property.id);

  let sync;
  try {
    sync = await syncRunFindings(admin, run);
  } catch (e) {
    console.error("[scan-findings] sync failed", (e as Error).message);
    return NextResponse.json({ error: "Run saved, findings sync failed", run_id: run.id }, { status: 500 });
  }
  return NextResponse.json({ run_id: run.id, property_id: property.id, property_name: property.name, sync }, { status: 201 });
}
