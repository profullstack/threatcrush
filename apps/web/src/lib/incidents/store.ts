import "server-only";
import { randomUUID } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  atLeast,
  findingsRoleOf,
  incidentRoleInScope,
  incidentRoleOf,
  incidentScopeIn,
  serverRoleOf,
  teamRoleOf,
  type Principal,
  type TeamRole,
} from "@/lib/access";
import {
  IncidentError,
  isStatus,
  isUuid,
  mergeReport,
  parseIncidentReport,
  SEVERITY_RANK,
  type IncidentReport,
  type ReportFinding,
  type Recommendation,
  type Severity,
  type TimelineEntry,
} from "./report";
import type { PageableIncident } from "./notify";

export { IncidentError } from "./report";

export interface IncidentRow {
  id: string;
  short_code: string;
  org_id: string;
  team_id: string | null;
  server_id: string | null;
  title: string;
  severity: Severity;
  source: string;
  status: "open" | "acknowledged" | "resolved";
  dedupe_key: string;
  summary: string;
  verdict: string | null;
  host: string | null;
  findings: ReportFinding[];
  timeline: TimelineEntry[];
  recommendations: Recommendation[];
  raise_count: number;
  assignee_id: string | null;
  created_by_user: string | null;
  created_by_agent_key: string | null;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  last_notified_at: string | null;
  created_at: string;
  updated_at: string;
}

/** What the caller should do after a raise: page (new, or escalated to critical) or not. */
export interface RaiseOutcome {
  incident: IncidentRow;
  created: boolean;
  page: boolean;
}

const SUMMARY_COLUMNS =
  "id, short_code, org_id, team_id, server_id, title, severity, source, status, host, raise_count, assignee_id, first_seen_at, last_seen_at, acknowledged_at, resolved_at, last_notified_at, created_at, updated_at";
const MAX_NOTE = 4000;

function incidentShortCode(title: string, id: string): string {
  const prefix = title.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 16) || "incident";
  return `${prefix}${id.replace(/-/g, "").slice(-14)}`;
}

export function pageable(row: IncidentRow): PageableIncident {
  return {
    id: row.id,
    short_code: row.short_code,
    org_id: row.org_id,
    team_id: row.team_id,
    title: row.title,
    severity: row.severity,
    host: row.host,
    summary: row.summary,
    findings_count: Array.isArray(row.findings) ? row.findings.length : 0,
  };
}

/** Which team an incident belongs to, and that the caller may raise it there. */
async function resolveTeam(admin: SupabaseClient, p: Principal, orgId: string, report: IncidentReport): Promise<string | null> {
  if (report.team_id) {
    const { data: team } = await admin.from("teams").select("id, org_id").eq("id", report.team_id).eq("org_id", orgId).maybeSingle();
    if (!team || !atLeast(await teamRoleOf(admin, p, team as { id: string; org_id: string }), "write")) {
      throw new IncidentError(404, "Team not found");
    }
    return report.team_id;
  }
  if (report.server_id) {
    const { data: server } = await admin.from("servers").select("id, org_id, fleet_id").eq("id", report.server_id).eq("org_id", orgId).maybeSingle();
    const s = server as { id: string; org_id: string; fleet_id: string | null } | null;
    if (!s || !atLeast(await serverRoleOf(admin, p, s), "write")) throw new IncidentError(404, "Server not found");
    if (!s.fleet_id) return null;
    const { data: fleet } = await admin.from("fleets").select("team_id").eq("id", s.fleet_id).maybeSingle();
    return (fleet as { team_id?: string } | null)?.team_id ?? null;
  }
  if (p.kind === "agent") {
    if (p.orgId !== orgId || !atLeast(p.role, "write")) throw new IncidentError(403, "Not authorized");
    return p.teamId;
  }
  if (!atLeast(await findingsRoleOf(admin, p, orgId), "write")) throw new IncidentError(403, "Not authorized");
  return null;
}

/**
 * Store a report: a new incident, or folded into the live one with the same
 * dedupe key. Access must already be settled; `by` records who raised it.
 */
export async function upsertIncident(
  admin: SupabaseClient,
  orgId: string,
  teamId: string | null,
  report: IncidentReport,
  by: { userId: string | null; agentKeyId: string | null },
): Promise<RaiseOutcome> {
  const now = new Date().toISOString();
  const live = async () => {
    const { data } = await admin
      .from("incidents")
      .select("*")
      .eq("org_id", orgId)
      .eq("dedupe_key", report.dedupe_key)
      .neq("status", "resolved")
      .maybeSingle();
    return data as IncidentRow | null;
  };

  let existing = await live();
  if (!existing) {
    const id = randomUUID();
    const { data, error } = await admin
      .from("incidents")
      .insert({
        id,
        short_code: incidentShortCode(report.title, id),
        org_id: orgId,
        team_id: teamId,
        server_id: report.server_id,
        title: report.title,
        severity: report.severity,
        source: report.source,
        dedupe_key: report.dedupe_key,
        summary: report.summary,
        verdict: report.verdict,
        host: report.host,
        findings: report.findings,
        timeline: report.timeline,
        recommendations: report.recommendations,
        created_by_user: by.userId,
        created_by_agent_key: by.agentKeyId,
        first_seen_at: now,
        last_seen_at: now,
      })
      .select("*")
      .single();
    if (!error && data) return { incident: data as IncidentRow, created: true, page: true };
    // Lost a race with a concurrent raise of the same key: fold into theirs.
    if ((error as { code?: string } | null)?.code !== "23505") throw new Error(`incident insert: ${error?.message}`);
    existing = await live();
    if (!existing) throw new Error("incident insert conflicted but no live incident was found");
  }

  const merged = mergeReport(existing, report);
  const severity = SEVERITY_RANK[report.severity] > SEVERITY_RANK[existing.severity] ? report.severity : existing.severity;
  const escalated = severity === "critical" && existing.severity !== "critical";
  const { data, error } = await admin
    .from("incidents")
    .update({
      title: report.title,
      summary: report.summary || existing.summary,
      verdict: report.verdict ?? existing.verdict,
      host: report.host ?? existing.host,
      severity,
      ...merged,
      raise_count: (existing.raise_count ?? 1) + 1,
      last_seen_at: now,
      updated_at: now,
    })
    .eq("id", existing.id)
    .select("*")
    .single();
  if (error || !data) throw new Error(`incident update: ${error?.message}`);
  return { incident: data as IncidentRow, created: false, page: escalated };
}

/** POST /api/orgs/[id]/incidents and MCP incidents_raise. */
export async function raiseIncident(admin: SupabaseClient, p: Principal, orgId: string, raw: unknown): Promise<RaiseOutcome> {
  const report = parseIncidentReport(raw);
  const teamId = await resolveTeam(admin, p, orgId, report);
  return upsertIncident(admin, orgId, teamId, report, {
    userId: p.kind === "user" ? p.userId : null,
    agentKeyId: p.kind === "agent" ? p.keyId : null,
  });
}

export async function listIncidents(
  admin: SupabaseClient,
  p: Principal,
  orgId: string,
  q: { status?: unknown; team_id?: unknown; limit?: unknown },
): Promise<{ incidents: Array<Record<string, unknown>>; counts: Record<"open" | "acknowledged" | "resolved", number> }> {
  const scope = await incidentScopeIn(admin, p, orgId);
  if (!scope) throw new IncidentError(403, "Not a member of this organization");
  const limit = Math.min(500, Math.max(1, Number(q.limit) || 100));

  // Everything the caller can see (counts), then the page they asked for.
  const { data, error } = await admin
    .from("incidents")
    .select(`${SUMMARY_COLUMNS}, findings`)
    .eq("org_id", orgId)
    .order("last_seen_at", { ascending: false })
    .limit(2000);
  if (error) throw new Error(`incidents list: ${error.message}`);
  const visible = ((data ?? []) as Array<IncidentRow>).filter((r) => incidentRoleInScope(scope, r) !== null);

  const counts = { open: 0, acknowledged: 0, resolved: 0 };
  for (const r of visible) counts[r.status]++;

  const statuses = typeof q.status === "string" && q.status && q.status !== "all"
    ? q.status.split(",").filter(isStatus)
    : null;
  const teamFilter = typeof q.team_id === "string" && q.team_id ? q.team_id : null;
  const rows = visible
    .filter((r) => (!statuses || statuses.includes(r.status)) && (!teamFilter || r.team_id === teamFilter))
    .slice(0, limit);

  const teamIds = [...new Set(rows.map((r) => r.team_id).filter(Boolean))] as string[];
  const teams = new Map<string, string>();
  if (teamIds.length) {
    const { data: t } = await admin.from("teams").select("id, name").in("id", teamIds);
    for (const team of (t ?? []) as Array<{ id: string; name: string }>) teams.set(team.id, team.name);
  }
  return {
    incidents: rows.map(({ findings, ...r }) => ({
      ...r,
      team_name: r.team_id ? teams.get(r.team_id) ?? null : null,
      findings_count: Array.isArray(findings) ? findings.length : 0,
    })),
    counts,
  };
}

async function loadWithRole(admin: SupabaseClient, p: Principal, orgId: string, id: string, min: TeamRole) {
  if (!isUuid(id)) throw new IncidentError(404, "Incident not found");
  const { data } = await admin.from("incidents").select("*").eq("id", id).eq("org_id", orgId).maybeSingle();
  const row = data as IncidentRow | null;
  const role = row ? await incidentRoleOf(admin, p, row) : null;
  if (!row || !role) throw new IncidentError(404, "Incident not found");
  if (!atLeast(role, min)) throw new IncidentError(403, `This needs ${min} access to the incident`);
  return { row, role };
}

export async function getIncident(admin: SupabaseClient, p: Principal, orgId: string, id: string) {
  const { row, role } = await loadWithRole(admin, p, orgId, id, "read");
  const [notes, notifications, team] = await Promise.all([
    admin.from("incident_notes").select("id, author_id, body, created_at").eq("incident_id", id).order("created_at", { ascending: true }),
    admin
      .from("incident_notifications")
      .select("id, user_id, channel, status, detail, created_at")
      .eq("incident_id", id)
      .order("created_at", { ascending: false })
      .limit(200),
    row.team_id ? admin.from("teams").select("id, name").eq("id", row.team_id).maybeSingle() : Promise.resolve({ data: null }),
  ]);
  const people = new Set<string>();
  for (const n of (notes.data ?? []) as Array<{ author_id: string | null }>) if (n.author_id) people.add(n.author_id);
  for (const n of (notifications.data ?? []) as Array<{ user_id: string }>) people.add(n.user_id);
  if (row.assignee_id) people.add(row.assignee_id);
  const members = await assignableMembers(admin, row);
  for (const m of members) people.delete(m.user_id);
  const names = new Map(members.map((m) => [m.user_id, m.name]));
  if (people.size) {
    const { data: prof } = await admin.from("user_profiles").select("id, email, display_name").in("id", [...people]);
    for (const x of (prof ?? []) as Array<{ id: string; email: string | null; display_name: string | null }>) {
      names.set(x.id, x.display_name || x.email || x.id.slice(0, 8));
    }
  }
  const nameOf = (id: string | null) => (id ? names.get(id) ?? null : null);
  return {
    incident: { ...row, team_name: (team.data as { name?: string } | null)?.name ?? null, assignee_name: nameOf(row.assignee_id) },
    role,
    members,
    notes: ((notes.data ?? []) as Array<{ author_id: string | null }>).map((n) => ({ ...n, author_name: nameOf(n.author_id) })),
    notifications: ((notifications.data ?? []) as Array<{ user_id: string }>).map((n) => ({ ...n, user_name: nameOf(n.user_id) })),
  };
}

/** Who an incident can be assigned to: its team's members, or the org's members when it has no team. */
async function assignableMembers(admin: SupabaseClient, row: { org_id: string; team_id: string | null }) {
  const { data } = row.team_id
    ? await admin.from("team_members").select("user_id").eq("team_id", row.team_id)
    : await admin.from("organization_members").select("user_id").eq("org_id", row.org_id).in("role", ["owner", "admin", "member"]);
  const ids = ((data ?? []) as Array<{ user_id: string }>).map((m) => m.user_id);
  if (!ids.length) return [];
  const { data: prof } = await admin.from("user_profiles").select("id, email, display_name").in("id", ids);
  const byId = new Map(((prof ?? []) as Array<{ id: string; email: string | null; display_name: string | null }>).map((x) => [x.id, x]));
  return ids.map((id) => ({ user_id: id, name: byId.get(id)?.display_name || byId.get(id)?.email || id.slice(0, 8) }));
}

export async function updateIncident(admin: SupabaseClient, p: Principal, orgId: string, id: string, body: Record<string, unknown>) {
  const { row } = await loadWithRole(admin, p, orgId, id, "write");
  const now = new Date().toISOString();
  const patch: Record<string, unknown> = {};

  if (body.status !== undefined) {
    if (!isStatus(body.status)) throw new IncidentError(400, "status must be open, acknowledged or resolved");
    patch.status = body.status;
    if (body.status === "acknowledged") patch.acknowledged_at = row.acknowledged_at ?? now;
    if (body.status === "resolved") patch.resolved_at = now;
    if (body.status === "open") patch.resolved_at = null;
    if (body.status === "open" && row.status === "resolved") {
      // Reopening must not collide with a newer live incident on the same key.
      const { data: clash } = await admin
        .from("incidents").select("id").eq("org_id", orgId).eq("dedupe_key", row.dedupe_key).neq("status", "resolved").neq("id", id).maybeSingle();
      if (clash) throw new IncidentError(409, "A newer open incident has the same key; work on that one");
    }
  }
  if (body.assignee_id !== undefined) {
    if (body.assignee_id === null) patch.assignee_id = null;
    else {
      if (!isUuid(body.assignee_id)) throw new IncidentError(400, "assignee_id must be a uuid or null");
      const members = await assignableMembers(admin, row);
      if (!members.some((m) => m.user_id === body.assignee_id)) {
        throw new IncidentError(400, row.team_id ? "The assignee must be on the incident's team" : "The assignee must be a member of the org");
      }
      patch.assignee_id = body.assignee_id;
    }
  }
  let note: string | null = null;
  if (body.note !== undefined) {
    if (typeof body.note !== "string" || !body.note.trim()) throw new IncidentError(400, "note must be a non-empty string");
    if (body.note.length > MAX_NOTE) throw new IncidentError(400, `note is longer than ${MAX_NOTE} characters`);
    note = body.note.trim();
  }
  if (!Object.keys(patch).length && note === null) throw new IncidentError(400, "Nothing to change: pass status, assignee_id or note");

  let incident = row;
  if (Object.keys(patch).length) {
    const { data, error } = await admin.from("incidents").update({ ...patch, updated_at: now }).eq("id", id).select("*").single();
    if (error || !data) {
      if ((error as { code?: string } | null)?.code === "23505") throw new IncidentError(409, "A newer open incident has the same key; work on that one");
      throw new Error(`incident update: ${error?.message}`);
    }
    incident = data as IncidentRow;
  }
  if (note !== null) {
    const { error } = await admin.from("incident_notes").insert({ incident_id: id, author_id: p.kind === "user" ? p.userId : null, body: note });
    if (error) throw new Error(`incident note: ${error.message}`);
  }
  return { incident };
}

/** A critical detection from ingest becomes (or bumps) an incident for the server's team. */
export interface CriticalDetection {
  id: string;
  organization_id: string;
  server_id: string;
  severity: Severity;
  title: string;
  description: string | null;
  source_ip: string | null;
  rule_id: string | null;
  detected_at: string;
}

export async function raiseDetectionIncidents(
  admin: SupabaseClient,
  detections: CriticalDetection[],
  servers: Map<string, { fleet_id: string | null; name: string | null }>,
): Promise<RaiseOutcome[]> {
  const out: RaiseOutcome[] = [];
  const fleetTeams = new Map<string, string | null>();
  // What actually happened: daemons 0.13.61+ attach the triggering line as
  // raw_metadata.evidence. Without it an incident could only repeat the rule's
  // description ("a critical log message"), which is what got paged.
  const evidence = new Map<string, Record<string, unknown> & { message?: string; at?: string; module?: string }>();
  const ids = detections.filter((d) => d.severity === "critical").map((d) => d.id);
  if (ids.length) {
    const { data } = await admin.from("detections").select("id, username, raw_metadata").in("id", ids);
    for (const r of (data ?? []) as Array<{
      id: string;
      username: string | null;
      raw_metadata: { evidence?: Record<string, unknown> & { message?: string; at?: string; module?: string } } | null;
    }>) {
      const ev = r.raw_metadata?.evidence;
      if (ev) evidence.set(r.id, { ...ev, username: r.username ?? undefined });
    }
  }
  for (const d of detections) {
    if (d.severity !== "critical") continue;
    try {
      const server = servers.get(d.server_id);
      let teamId: string | null = null;
      if (server?.fleet_id) {
        if (!fleetTeams.has(server.fleet_id)) {
          const { data } = await admin.from("fleets").select("team_id").eq("id", server.fleet_id).maybeSingle();
          fleetTeams.set(server.fleet_id, (data as { team_id?: string } | null)?.team_id ?? null);
        }
        teamId = fleetTeams.get(server.fleet_id) ?? null;
      }
      const key = `detection:${d.server_id}:${d.rule_id || d.title}`.slice(0, 200);
      const at = new Date(d.detected_at).toISOString();
      const ev = evidence.get(d.id);
      const line = typeof ev?.message === "string" ? ev.message.slice(0, 500) : null;
      const targetAccount = [ev?.username, ev?.user, ev?.ssh_user, ev?.account].find((x) => typeof x === "string" && x.trim()) as string | undefined;
      const systemAccount = typeof ev?.system_account === "string" ? ev.system_account : null;
      const systemUid = typeof ev?.system_uid === "string" || typeof ev?.system_uid === "number" ? String(ev.system_uid) : null;
      const accountLines = [
        targetAccount ? `Target account: ${targetAccount}` : null,
        systemAccount ? `System account: ${systemAccount}${systemUid ? ` (uid ${systemUid})` : ""}` : null,
        !systemAccount && systemUid ? `System account UID: ${systemUid} (name unavailable)` : null,
        typeof ev?.key_type === "string" || typeof ev?.fingerprint === "string"
          ? `SSH key: ${[ev.key_type, ev.fingerprint].filter((x) => typeof x === "string").join(" ")}`
          : null,
      ].filter((x): x is string => Boolean(x));
      const summaryAccounts = accountLines.filter((entry) => entry.startsWith("Target account:") || entry.startsWith("System account"));
      const summary = [...summaryAccounts, line ?? `${d.title}${d.source_ip ? ` from ${d.source_ip}` : ""}`].filter(Boolean).join(" — ").slice(0, 1000);
      const details = [line, d.description, ...accountLines].filter(Boolean).join("\n\n").slice(0, 4000);
      out.push(
        await upsertIncident(
          admin,
          d.organization_id,
          teamId,
          {
            team_id: teamId,
            server_id: d.server_id,
            title: d.title.slice(0, 300),
            severity: "critical",
            source: "daemon",
            dedupe_key: key,
            summary: [summary, d.description].filter(Boolean).join("\n\n").slice(0, 4000),
            verdict: null,
            host: server?.name ?? null,
            findings: [{ id: `detection:${d.rule_id || d.title}`.slice(0, 120), module: "daemon", severity: "critical", title: d.title.slice(0, 300), ...(details ? { detail: details } : {}), evidence: "evidence", at }],
            timeline: [{ at, module: "daemon", summary, evidence: true, ref: `detection:${d.id}` }],
            recommendations: [],
          },
          { userId: null, agentKeyId: null },
        ),
      );
    } catch (err) {
      console.error(`[incidents] detection ${d.id} -> incident failed:`, (err as Error).message);
    }
  }
  return out;
}
