import { createHash } from "node:crypto";
import { after, NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { hashSecret } from "@/lib/access";
import { classifyRepositoryFindings, parseRepositoryFindings } from "@/lib/repository-warnings";
import { parseIncidentReport } from "@/lib/incidents/report";
import { pageable, upsertIncident } from "@/lib/incidents/store";
import { notifyIncident } from "@/lib/incidents/notify";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function POST(req: NextRequest) {
  const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (!/^tc_repo_[\w-]{43}$/.test(token)) return NextResponse.json({ error: "Repository connection token required" }, { status: 401 });
  const admin = getSupabaseAdmin();
  const found = await admin.from("github_repository_policies").select("id, org_id, team_id, full_name, silence_warnings, silence_examples").eq("token_hash", hashSecret(token)).maybeSingle();
  if (found.error) return NextResponse.json({ error: "Could not load repository policy" }, { status: 503 });
  if (!found.data) return NextResponse.json({ error: "Invalid repository connection" }, { status: 401 });
  const policy = found.data;
  // Bound the body while reading, including requests without Content-Length.
  const reader = req.body?.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) for (;;) {
    const part = await reader.read();
    if (part.done) break;
    size += part.value.byteLength;
    if (size > 2 * 1024 * 1024) { await reader.cancel(); return NextResponse.json({ error: "Report too large" }, { status: 413 }); }
    chunks.push(part.value);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  let body, findings;
  try {
    body = JSON.parse(raw);
    if (body.repository?.toLowerCase() !== policy.full_name || !/^[0-9]{1,30}$/.test(body.run_id)) throw new Error("Repository and run ID must match the connection");
    findings = parseRepositoryFindings(body.findings);
  } catch (e) { return NextResponse.json({ error: (e as Error).message }, { status: 400 }); }
  const classified = classifyRepositoryFindings(findings, policy);
  let incidentId: string | null = null;
  try {
    if (classified.critical.length) {
      // Stable across runs and line movement. A repeat report updates the live
      // incident; only a new critical set (or a resolved incident) pages again.
      const identities = [...new Set(classified.critical.map((f) => `${f.ruleId}:${f.file}:${f.fingerprint}`))].sort();
      const key = createHash("sha256").update(`${policy.id}\n${identities.join("\n")}`).digest("hex");
      const url = `https://github.com/${policy.full_name}/actions/runs/${body.run_id}`;
      const report = parseIncidentReport({
        source: "manual", severity: "critical", title: `Critical repository findings: ${policy.full_name}`,
        dedupe_key: `repo-critical:${key}`, summary: `${classified.critical.length} critical finding(s). Review ${url}. Repository warning silences do not apply to critical findings.`,
        findings: classified.critical.slice(0, 200).map((f) => ({ id: f.fingerprint, module: "repository-scan", severity: "critical", title: f.ruleId, detail: `${f.file}:${f.line}`, evidence: "inference" })),
      });
      const outcome = await upsertIncident(admin, policy.org_id, policy.team_id, report, { userId: null, agentKeyId: null });
      incidentId = outcome.incident.id;
      if (outcome.page) after(async () => { await notifyIncident(pageable(outcome.incident), admin); });
    }
    const saved = await admin.from("github_repository_policies").update({ last_report_at: new Date().toISOString(), last_counts: classified.counts }).eq("id", policy.id);
    if (saved.error) throw new Error("Could not record report");
    return NextResponse.json({ visible: classified.visible, counts: classified.counts, incident_id: incidentId, settings_url: "https://threatcrush.com/account#repository-alerts" }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Could not record critical incident or report; retry this report" }, { status: 503 });
  }
}
