import { NextRequest, NextResponse } from "next/server";
import {
  CAC_TAG,
  CIS_CATALOG_CHECKED_AT,
  CIS_DISCLAIMER,
  cisEditionCaveat,
  cisMappingCell,
  cisMappingFields,
  currentCisEdition,
  renderTextPdf,
  resolveCisMapping,
  type CisProfile,
} from "@threatcrush/scan/cis";
import { requireOrgScope, visibleServerIds } from "@/lib/route-access";

export const runtime = "nodejs";

function stringField(details: Record<string, unknown>, key: string): string | null {
  const value = details[key];
  return typeof value === "string" && value.length > 0 && value.length < 64 ? value : null;
}

// GET /api/orgs/:id/hardening-report?format=md|json|pdf
// CIS mappings are re-derived here from the shared pinned crosswalk using the
// host OS the agent reported; ids sent by the agent are never trusted.
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id: orgId } = await params;
  const access = await requireOrgScope(req, orgId);
  if ("error" in access) return access.error;
  const format = new URL(req.url).searchParams.get("format") ?? "md";
  if (format !== "md" && format !== "json" && format !== "pdf") return NextResponse.json({ error: "format must be md, json or pdf" }, { status: 400 });

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
  const profiles = new Map<string, { profile: CisProfile | null; osId: string | null; osVersion: string | null }>();
  const checks = (findings ?? []).map((finding) => {
    const server = serverMap.get(finding.server_id);
    const fleet = server?.fleet_id ? fleetMap.get(server.fleet_id) : null;
    const details = finding.details && typeof finding.details === "object" && !Array.isArray(finding.details)
      ? finding.details as Record<string, unknown>
      : {};
    // Older agents only sent the profile on a mapped finding; newer ones send
    // the host OS on every finding.
    const osId = stringField(details, "cis_host_os_id") ?? stringField(details, "cis_profile_os_id");
    const osVersion = stringField(details, "cis_host_os_version") ?? stringField(details, "cis_profile_os_version");
    const resolved = resolveCisMapping(finding.finding_key, "harden", osId, osVersion);
    const fields = cisMappingFields(resolved);
    profiles.set(`${osId ?? ""} ${osVersion ?? ""}`, { profile: resolved.profile, osId, osVersion });
    const evidence = Object.fromEntries(Object.entries(details).filter(([key]) => !key.startsWith("cis_")));
    return {
      finding_key: finding.finding_key,
      status: finding.status,
      severity: finding.severity,
      title: finding.title,
      evidence,
      recommendation: finding.recommendation,
      observed_at: finding.observed_at,
      server: server?.name || server?.hostname || finding.server_id,
      fleet: fleet?.name ?? null,
      host_os: osId && osVersion ? `${osId} ${osVersion}` : null,
      cis_control_ids: fields.cis_control_ids,
      mapping_status: fields.cis_mapping_status,
      mapping_coverage: fields.cis_mapping_coverage,
      mapping_controls: fields.cis_controls,
      mapping_benchmark: fields.cis_mapping_status === "verified" ? fields.cis_mapping_benchmark : undefined,
      mapping_source: fields.cis_mapping_status === "verified" ? fields.cis_mapping_source : undefined,
      mapping_reason: fields.cis_unmapped_reason,
      mapping_detail: cisMappingCell(resolved),
    };
  });
  const caveats = [...profiles.values()].map(({ profile, osId, osVersion }) =>
    `${osId && osVersion ? `${osId} ${osVersion}` : "Unknown OS"}: ${cisEditionCaveat(profile, currentCisEdition(osId, osVersion))}`);
  const mappedChecks = checks.filter((check) => check.mapping_status === "verified").length;
  const report = {
    schema_version: 2,
    generated_at: new Date().toISOString(),
    disclaimer: CIS_DISCLAIMER,
    benchmark_catalog_checked_at: CIS_CATALOG_CHECKED_AT,
    crosswalk_source: `ComplianceAsCode ${CAC_TAG}`,
    organization: org?.name ?? "ThreatCrush organization",
    assessment: "partial" as const,
    mapped_controls: new Set(checks.flatMap((check) => check.mapping_status === "verified" ? check.cis_control_ids : [])).size,
    mapped_checks: mappedChecks,
    unmapped_checks: checks.length - mappedChecks,
    total_checks: checks.length,
    checks,
    limitations: [
      "This export contains ThreatCrush hardening evidence only; it does not assess a CIS Benchmark profile.",
      ...[...new Set(caveats)],
      "A mapping with partial coverage means the check reads the same setting with a narrower scope or looser threshold: its FAIL is a real finding against the control, its PASS does not satisfy the control.",
      "Unmapped checks have no matching control in the pinned profile. Unverified checks come from a host whose OS has no pinned profile, or from an agent too old to report its OS.",
      "PASS, FAIL, and WARN are ThreatCrush check results, not CIS control results or a certification claim.",
    ],
  };

  if (format === "json") {
    return new NextResponse(`${JSON.stringify(report, null, 2)}\n`, {
      headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": 'attachment; filename="threatcrush-hardening-evidence.json"' },
    });
  }
  const cell = (value: string) => value.replace(/[|\r\n]+/g, " ").trim();
  const rows = report.checks.map((check) => {
    const facts = Object.keys(check.evidence).length ? ` - ${JSON.stringify(check.evidence)}` : "";
    const evidence = cell(`${check.status.toUpperCase()}: ${check.title}${facts}`);
    const recommendation = cell(check.recommendation ?? "-");
    return `| ${check.fleet ?? "-"} | ${cell(check.server)} | ${check.host_os ?? "unknown"} | ${check.finding_key} | ${check.status.toUpperCase()} | ${cell(check.mapping_detail)} | ${evidence} | ${recommendation} | ${check.observed_at ?? "-"} |`;
  });
  const markdown = [
    `# ThreatCrush hardening evidence - ${report.organization}`,
    "",
    `> ${report.disclaimer}`,
    "",
    `- Generated: ${report.generated_at}`,
    `- CIS crosswalk: ${report.crosswalk_source} (CIS edition catalog checked ${report.benchmark_catalog_checked_at})`,
    `- Findings: ${report.total_checks}`,
    `- Findings mapped to CIS controls: ${report.mapped_checks} (${report.mapped_controls} distinct control ids); unmapped or unverified: ${report.unmapped_checks}`,
    "",
    "| Fleet | Server | OS | Check | Result | CIS mapping | Evidence | Recommendation | Observed |",
    "|---|---|---|---|---|---|---|---|---|",
    ...rows,
    "",
    "## Limitations",
    "",
    ...report.limitations.map((limitation) => `- ${limitation}`),
    "",
  ].join("\n");
  if (format === "pdf") {
    return new NextResponse(Buffer.from(renderTextPdf(markdown)), {
      headers: { "Content-Type": "application/pdf", "Content-Disposition": 'attachment; filename="threatcrush-hardening-evidence.pdf"' },
    });
  }
  return new NextResponse(markdown, {
    headers: { "Content-Type": "text/markdown; charset=utf-8", "Content-Disposition": 'attachment; filename="threatcrush-hardening-evidence.md"' },
  });
}
