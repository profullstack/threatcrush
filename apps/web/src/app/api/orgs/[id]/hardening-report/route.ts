import { NextRequest, NextResponse } from "next/server";
import { requireOrgScope, visibleServerIds } from "@/lib/route-access";

export const runtime = "nodejs";

// GET /api/orgs/:id/hardening-report?format=md|json
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id: orgId } = await params;
  const access = await requireOrgScope(req, orgId);
  if ("error" in access) return access.error;
  const format = new URL(req.url).searchParams.get("format") ?? "md";
  if (format !== "md" && format !== "json") return NextResponse.json({ error: "format must be md or json" }, { status: 400 });

  const serverIds = await visibleServerIds(access.admin, orgId, access.scope);
  if (serverIds?.length === 0) return NextResponse.json({ error: "No visible servers" }, { status: 403 });
  let findingsQuery = access.admin.from("hardening_findings")
    .select("id, server_id, finding_key, severity, status, title, recommendation, observed_at, details")
    .eq("organization_id", orgId).order("observed_at", { ascending: false });
  if (serverIds) findingsQuery = findingsQuery.in("server_id", serverIds);
  const [{ data: findings, error }, { data: org }] = await Promise.all([
    findingsQuery,
    access.admin.from("organizations").select("name").eq("id", orgId).maybeSingle(),
  ]);
  if (error) return NextResponse.json({ error: "Could not build hardening report" }, { status: 500 });
  const ids = [...new Set((findings ?? []).map((item) => item.server_id))];
  const { data: servers, error: serversError } = ids.length
    ? await access.admin.from("servers").select("id, name, hostname, fleet_id").eq("org_id", orgId).in("id", ids)
    : { data: [], error: null };
  if (serversError) return NextResponse.json({ error: "Could not load report server details" }, { status: 500 });
  const serverMap = new Map((servers ?? []).map((server) => [server.id, server]));
  const fleetIds = [...new Set((servers ?? []).flatMap((server) => server.fleet_id ? [server.fleet_id] : []))];
  const { data: fleets } = fleetIds.length ? await access.admin.from("fleets").select("id, name, team_id").in("id", fleetIds) : { data: [] };
  const fleetMap = new Map((fleets ?? []).map((fleet) => [fleet.id, fleet]));
  const report = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    organization: org?.name ?? "ThreatCrush organization",
    assessment: "partial" as const,
    mapped_controls: 0,
    total_checks: (findings ?? []).length,
    checks: (findings ?? []).map((finding) => {
      const server = serverMap.get(finding.server_id);
      const fleet = server?.fleet_id ? fleetMap.get(server.fleet_id) : null;
      return {
        finding_key: finding.finding_key,
        status: finding.status,
        severity: finding.severity,
        title: finding.title,
        evidence: finding.details,
        recommendation: finding.recommendation,
        observed_at: finding.observed_at,
        server: server?.name || server?.hostname || finding.server_id,
        fleet: fleet?.name ?? null,
        cis_control_ids: [] as string[],
        mapping_status: "unverified" as const,
      };
    }),
    limitations: [
      "This export contains ThreatCrush hardening evidence only; it does not assess a CIS Benchmark profile.",
      "No check-to-control crosswalk has been verified against the installed host benchmark edition, so no CIS control IDs are claimed.",
      "PASS, FAIL, and WARN are ThreatCrush check results, not CIS control results or a certification claim.",
    ],
  };

  if (format === "json") {
    return new NextResponse(`${JSON.stringify(report, null, 2)}\n`, {
      headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": 'attachment; filename="threatcrush-hardening-evidence.json"' },
    });
  }
  const rows = report.checks.map((check) => {
    const evidence = `${check.status.toUpperCase()}: ${check.title}${check.evidence ? ` — ${JSON.stringify(check.evidence)}` : ""}`.replace(/[|\r\n]+/g, " ");
    const recommendation = (check.recommendation ?? "—").replace(/[|\r\n]+/g, " ");
    return `| ${check.fleet ?? "—"} | ${check.server} | ${check.finding_key} | ${check.status.toUpperCase()} | Unverified | ${evidence} | ${recommendation} |`;
  });
  const markdown = [
    `# ThreatCrush hardening evidence — ${report.organization}`,
    "",
    "> Partial ThreatCrush evidence only. This is not a CIS Benchmark assessment or certification report.",
    "",
    `- Generated: ${report.generated_at}`,
    `- Findings: ${report.total_checks}`,
    `- Verified CIS mappings: ${report.mapped_controls}`,
    "",
    "| Fleet | Server | Check | Result | CIS mapping | Evidence | Recommendation |",
    "|---|---|---|---|---|---|---|",
    ...rows,
    "",
    "## Limitations",
    "",
    ...report.limitations.map((limitation) => `- ${limitation}`),
    "",
  ].join("\n");
  return new NextResponse(markdown, {
    headers: { "Content-Type": "text/markdown; charset=utf-8", "Content-Disposition": 'attachment; filename="threatcrush-hardening-evidence.md"' },
  });
}
