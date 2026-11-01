import { NextRequest, NextResponse } from "next/server";
import { requireOrgScope, visibleServerIds } from "@/lib/route-access";

export const runtime = "nodejs";
const UBUNTU_2404_CIS_CONTROL_SOURCE = "https://github.com/ComplianceAsCode/content/blob/v0.1.78/controls/cis_ubuntu2404.yml";

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
      const details = finding.details && typeof finding.details === "object" && !Array.isArray(finding.details)
        ? finding.details as Record<string, unknown>
        : {};
      const cisIds = Array.isArray(details.cis_control_ids)
        ? details.cis_control_ids.filter((value): value is string => typeof value === "string" && /^\d+(?:\.\d+)*$/.test(value))
        : [];
      const verifiedRootLoginMapping = finding.finding_key === "ssh-root-login" &&
        details.cis_mapping_status === "verified" &&
        details.cis_profile_os_id === "ubuntu" &&
        details.cis_profile_os_version === "24.04" &&
        details.cis_profile_name === "CIS Ubuntu Linux 24.04 LTS" &&
        details.cis_profile_version === "1.0.0" &&
        details.cis_mapping_source === UBUNTU_2404_CIS_CONTROL_SOURCE &&
        cisIds.length === 1 && cisIds[0] === "5.1.20";
      const mappingStatus = verifiedRootLoginMapping ? "verified" as const : "unverified" as const;
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
        cis_control_ids: mappingStatus === "verified" ? ["5.1.20"] : [],
        mapping_status: mappingStatus,
        mapping_benchmark: mappingStatus === "verified" ? "CIS Ubuntu Linux 24.04 LTS v1.0.0" : undefined,
        mapping_source: mappingStatus === "verified" ? UBUNTU_2404_CIS_CONTROL_SOURCE : undefined,
      };
    }),
    limitations: [
      "This export contains ThreatCrush hardening evidence only; it does not assess a CIS Benchmark profile.",
      "The verified SSH mapping uses the CIS Ubuntu 24.04 LTS v1.0.0 implementation. The current CIS catalog lists v2.0.0; no mapping to v2.0.0 is claimed. Older findings without mapping metadata remain unverified.",
      "PASS, FAIL, and WARN are ThreatCrush check results, not CIS control results or a certification claim.",
    ],
  };
  const mappedControls = new Set(report.checks.flatMap((check) => check.mapping_status === "verified" ? check.cis_control_ids : []));
  report.mapped_controls = mappedControls.size;

  if (format === "json") {
    return new NextResponse(`${JSON.stringify(report, null, 2)}\n`, {
      headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": 'attachment; filename="threatcrush-hardening-evidence.json"' },
    });
  }
  const rows = report.checks.map((check) => {
    const evidence = `${check.status.toUpperCase()}: ${check.title}${check.evidence ? ` — ${JSON.stringify(check.evidence)}` : ""}`.replace(/[|\r\n]+/g, " ");
    const recommendation = (check.recommendation ?? "—").replace(/[|\r\n]+/g, " ");
    const reference = [check.mapping_benchmark, check.mapping_source].filter(Boolean).join("; ");
    const mapping = check.cis_control_ids.length ? `${check.cis_control_ids.join(", ")}${reference ? ` (${reference})` : ""}` : "Unverified";
    return `| ${check.fleet ?? "—"} | ${check.server} | ${check.finding_key} | ${check.status.toUpperCase()} | ${mapping} | ${evidence} | ${recommendation} |`;
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
