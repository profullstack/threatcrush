import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * One organization's security state as something an AI agent can act on:
 * every open hardening finding, per server, with the fix ThreatCrush
 * recommends, plus a summary of what attacked it recently. Rendered as a
 * prompt ("Copy fix prompt") and served read-only at /r/<token>.
 *
 * Deliberately left out: raw event metadata, request bodies, usernames
 * attempted, anything from a config. Only what is needed to fix things.
 */

export const DETECTION_WINDOW_HOURS = 24;
const OPEN_STATUSES = ["fail", "warn", "acknowledged"];
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export interface ReportFinding {
  key: string;
  severity: string;
  status: string;
  title: string;
  recommendation: string | null;
  observed_at: string;
}

export interface ReportServer {
  id: string;
  name: string;
  hostname: string | null;
  version: string | null;
  last_seen: string | null;
  findings: ReportFinding[];
}

export interface ReportAttack {
  title: string;
  severity: string;
  count: number;
  sources: number;
}

export interface FixReport {
  org: { name: string; slug: string };
  generated_at: string;
  servers: ReportServer[];
  open_findings: number;
  detections: { window_hours: number; total: number; top: ReportAttack[]; top_sources: Array<{ ip: string; count: number }> };
}

const bySeverity = (a: { severity: string }, b: { severity: string }) =>
  (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);

export async function loadFixReport(admin: SupabaseClient, orgId: string, now = new Date()): Promise<FixReport | null> {
  const { data: org } = await admin.from("organizations").select("name, slug").eq("id", orgId).maybeSingle();
  if (!org) return null;

  const since = new Date(now.getTime() - DETECTION_WINDOW_HOURS * 3600_000).toISOString();
  const [{ data: servers }, { data: findings }, { data: detections }] = await Promise.all([
    admin.from("servers").select("id, name, hostname, threatcrushd_version, last_seen").eq("org_id", orgId),
    admin.from("hardening_findings")
      .select("server_id, finding_key, severity, status, title, recommendation, observed_at")
      .eq("organization_id", orgId)
      .in("status", OPEN_STATUSES),
    admin.from("detections")
      .select("title, severity, source_ip, occurrences")
      .eq("organization_id", orgId)
      .gte("detected_at", since)
      .limit(5000),
  ]);

  return buildFixReport(org, servers ?? [], findings ?? [], detections ?? [], now);
}

export function buildFixReport(
  org: { name: string; slug: string },
  servers: Array<{ id: string; name: string; hostname: string | null; threatcrushd_version: string | null; last_seen: string | null }>,
  findings: Array<{ server_id: string; finding_key: string; severity: string; status: string; title: string; recommendation: string | null; observed_at: string }>,
  detections: Array<{ title: string; severity: string; source_ip: string | null; occurrences?: number | null }>,
  now = new Date(),
): FixReport {
  const reportServers: ReportServer[] = servers.map((s) => ({
    id: s.id,
    name: s.name,
    hostname: s.hostname,
    version: s.threatcrushd_version,
    last_seen: s.last_seen,
    findings: findings
      .filter((f) => f.server_id === s.id)
      .map((f) => ({
        key: f.finding_key,
        severity: f.severity,
        status: f.status,
        title: f.title,
        recommendation: f.recommendation,
        observed_at: f.observed_at,
      }))
      .sort(bySeverity),
  }));
  // Servers with something to fix first.
  reportServers.sort((a, b) => b.findings.length - a.findings.length || a.name.localeCompare(b.name));

  const attacks = new Map<string, { title: string; severity: string; count: number; sources: Set<string> }>();
  const sources = new Map<string, number>();
  let total = 0;
  for (const d of detections) {
    const n = Math.max(1, d.occurrences ?? 1);
    total += n;
    const entry = attacks.get(d.title) ?? { title: d.title, severity: d.severity, count: 0, sources: new Set<string>() };
    entry.count += n;
    if (d.source_ip) entry.sources.add(d.source_ip);
    attacks.set(d.title, entry);
    if (d.source_ip) sources.set(d.source_ip, (sources.get(d.source_ip) ?? 0) + n);
  }

  return {
    org: { name: org.name, slug: org.slug },
    generated_at: now.toISOString(),
    servers: reportServers,
    open_findings: reportServers.reduce((n, s) => n + s.findings.length, 0),
    detections: {
      window_hours: DETECTION_WINDOW_HOURS,
      total,
      top: [...attacks.values()]
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
        .map((a) => ({ title: a.title, severity: a.severity, count: a.count, sources: a.sources.size })),
      top_sources: [...sources.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count })),
    },
  };
}

/** The report as a prompt an AI coding or ops agent can work through. */
export function renderFixPrompt(report: FixReport): string {
  const lines: string[] = [];
  lines.push(`# ThreatCrush fix report: ${report.org.name}`);
  lines.push("");
  lines.push(`Generated ${report.generated_at}. ${report.open_findings} open hardening finding${report.open_findings === 1 ? "" : "s"} across ${report.servers.length} server${report.servers.length === 1 ? "" : "s"}.`);
  lines.push("");
  lines.push("## Instructions");
  lines.push("");
  lines.push("You are fixing the security findings ThreatCrush reported for the servers below. For each open finding:");
  lines.push("");
  lines.push("1. Connect to that server and confirm the finding is still true before changing anything.");
  lines.push("2. Apply the recommended fix. Keep the change minimal, back up any file before you edit it, and do not lock yourself out (for SSH changes, keep your current session open and test a second login before closing it).");
  lines.push("3. Verify by running `threatcrush harden` on the server. It re-checks everything and uploads the new results, which closes the finding on the dashboard.");
  lines.push("4. Report what you changed on each server, and anything you could not fix and why.");
  lines.push("");
  lines.push("Do not unban or allowlist any address from the attack summary. Those bans are ThreatCrush working.");

  const withFindings = report.servers.filter((s) => s.findings.length > 0);
  lines.push("");
  lines.push("## Open findings");
  if (withFindings.length === 0) {
    lines.push("");
    lines.push("None. Every hardening check passes on every server.");
  }
  for (const s of withFindings) {
    lines.push("");
    lines.push(`### ${s.name}${s.hostname && s.hostname !== s.name ? ` (${s.hostname})` : ""}`);
    lines.push("");
    lines.push(`threatcrushd ${s.version ? `v${s.version}` : "version unknown"}, last seen ${s.last_seen ?? "never"}.`);
    lines.push("");
    for (const f of s.findings) {
      lines.push(`- **[${f.severity}] ${f.title}** (\`${f.key}\`, ${f.status})`);
      if (f.recommendation) lines.push(`  Fix: ${f.recommendation}`);
    }
  }

  const clean = report.servers.filter((s) => s.findings.length === 0).map((s) => s.name);
  if (clean.length > 0 && withFindings.length > 0) {
    lines.push("");
    lines.push(`No open findings: ${clean.join(", ")}.`);
  }

  const d = report.detections;
  lines.push("");
  lines.push(`## Attacks in the last ${d.window_hours}h (context, already handled)`);
  lines.push("");
  if (d.total === 0) {
    lines.push("No detections.");
  } else {
    lines.push(`${d.total} detection${d.total === 1 ? "" : "s"}. ThreatCrush bans the source on first detection and doubles the ban on each repeat. Use this to decide what else to harden (for example, paths being probed that should not exist).`);
    lines.push("");
    for (const a of d.top) lines.push(`- ${a.count}x [${a.severity}] ${a.title} (${a.sources} source${a.sources === 1 ? "" : "s"})`);
    if (d.top_sources.length > 0) {
      lines.push("");
      lines.push(`Busiest sources: ${d.top_sources.map((s) => `${s.ip} (${s.count})`).join(", ")}.`);
    }
  }
  lines.push("");
  return lines.join("\n");
}
