import "server-only";
import { randomInt, randomUUID } from "node:crypto";
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
import { forensicEvidence, type DetectionEvidence } from "./forensics";
import { findSecret } from "./secret-guard";

export { IncidentError } from "./report";

export interface IncidentRow {
  id: string;
  short_code: string;
  human_code: string;
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
  fix_status: FixStatus;
  fix_pr_url: string | null;
  fix_test_status: FixTestStatus;
  fix_test_summary: string | null;
  fix_test_url: string | null;
  fix_verification: string | null;
  fix_blocked_reason: string | null;
  fix_updated_at: string | null;
  fix_updated_by_user: string | null;
  fix_updated_by_agent_key: string | null;
  created_by_user: string | null;
  created_by_agent_key: string | null;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  resolution?: { reason: string; action: string; verification: string; actor_user_id: string | null; actor_agent_key_id: string | null; at: string } | null;
  last_notified_at: string | null;
  created_at: string;
  updated_at: string;
}

export type FixStatus = "unassigned" | "assigned" | "in_progress" | "blocked" | "pr_open" | "testing" | "tested" | "fixed" | "false_positive";
export type FixTestStatus = "not_run" | "running" | "passed" | "failed" | "skipped";

const FIX_STATUSES: FixStatus[] = ["unassigned", "assigned", "in_progress", "blocked", "pr_open", "testing", "tested", "fixed", "false_positive"];
const FIX_TEST_STATUSES: FixTestStatus[] = ["not_run", "running", "passed", "failed", "skipped"];

/** What the caller should do after a raise: page (new, or escalated to critical) or not. */
export interface RaiseOutcome {
  incident: IncidentRow;
  created: boolean;
  page: boolean;
}

const SUMMARY_COLUMNS =
  "id, short_code, human_code, org_id, team_id, server_id, title, severity, source, status, host, raise_count, assignee_id, fix_status, fix_test_status, first_seen_at, last_seen_at, acknowledged_at, resolved_at, last_notified_at, created_at, updated_at";
const MAX_NOTE = 4000;
const FIX_WORK_FIELDS = new Set(["status", "pr_url", "test_status", "test_summary", "test_url", "verification", "blocked_reason"]);

function validHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && Boolean(url.hostname) && !url.username && !url.password;
  } catch {
    return false;
  }
}

function incidentShortCode(title: string, id: string): string {
  const prefix = title.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 16) || "incident";
  return `${prefix}${id.replace(/-/g, "").slice(-14)}`;
}

async function availableHumanCode(admin: SupabaseClient): Promise<string> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
    const { data, error } = await admin.from("incidents").select("id").eq("human_code", code).maybeSingle();
    if (error) throw new Error(`incident code lookup: ${error.message}`);
    if (!data) return code;
  }
  throw new Error("could not allocate a unique six-digit incident code");
}

export function pageable(row: IncidentRow): PageableIncident {
  return {
    id: row.id,
    short_code: row.short_code,
    human_code: row.human_code,
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
    for (let attempt = 0; attempt < 10; attempt++) {
      const humanCode = await availableHumanCode(admin);
      const { data, error } = await admin
        .from("incidents")
        .insert({
          id,
          short_code: incidentShortCode(report.title, id),
          human_code: humanCode,
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
      // A concurrent raise of the same dedupe key should fold into its row.
      if ((error as { code?: string } | null)?.code !== "23505") throw new Error(`incident insert: ${error?.message}`);
      existing = await live();
      if (existing) break;
      const { data: collision, error: collisionError } = await admin
        .from("incidents").select("id").eq("human_code", humanCode).maybeSingle();
      if (collisionError) throw new Error(`incident code collision check: ${collisionError.message}`);
      if (collision) continue;
      throw new Error(`incident insert: ${error?.message}`);
    }
    if (!existing) throw new Error("incident code allocation retries exhausted");
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
  const rowIds = rows.map((r) => r.id);
  const { data: assignmentRows, error: assignmentError } = rowIds.length
    ? await admin.from("incident_fix_assignees").select("incident_id, user_id, sort_order").in("incident_id", rowIds).order("sort_order", { ascending: true })
    : { data: [], error: null };
  if (assignmentError) throw new Error(`incidents assignees: ${assignmentError.message}`);
  const assigneeIds = [...new Set(((assignmentRows ?? []) as Array<{ user_id: string }>).map((a) => a.user_id))];
  const memberNames = new Map<string, { name: string; email: string | null }>();
  if (assigneeIds.length) {
    const { data: profiles, error: profileError } = await admin.from("user_profiles").select("id, email, display_name").in("id", assigneeIds);
    if (profileError) throw new Error(`incidents assignee profiles: ${profileError.message}`);
    for (const profile of (profiles ?? []) as Array<{ id: string; email: string | null; display_name: string | null }>) {
      memberNames.set(profile.id, { name: profile.display_name || profile.email || profile.id.slice(0, 8), email: profile.email });
    }
  }
  const assigneesByIncident = new Map<string, Array<{ user_id: string; name: string; email: string | null }>>();
  for (const a of (assignmentRows ?? []) as Array<{ incident_id: string; user_id: string }>) {
    const profile = memberNames.get(a.user_id);
    const list = assigneesByIncident.get(a.incident_id) ?? [];
    list.push({ user_id: a.user_id, name: profile?.name ?? a.user_id.slice(0, 8), email: profile?.email ?? null });
    assigneesByIncident.set(a.incident_id, list);
  }
  return {
    incidents: rows.map(({ findings, ...r }) => ({
      ...r,
      team_name: r.team_id ? teams.get(r.team_id) ?? null : null,
      assignees: assigneesByIncident.get(r.id) ?? [],
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
  const [notes, notifications, team, assignedRows, fixEvents] = await Promise.all([
    admin.from("incident_notes").select("id, author_id, body, created_at").eq("incident_id", id).order("created_at", { ascending: true }),
    admin
      .from("incident_notifications")
      .select("id, user_id, channel, status, detail, created_at")
      .eq("incident_id", id)
      .order("created_at", { ascending: false })
      .limit(200),
    row.team_id ? admin.from("teams").select("id, name").eq("id", row.team_id).maybeSingle() : Promise.resolve({ data: null }),
    admin.from("incident_fix_assignees").select("user_id, assigned_at, sort_order").eq("incident_id", id).order("sort_order", { ascending: true }).order("assigned_at", { ascending: true }),
    admin.from("incident_fix_events").select("id, actor_label, event_type, details, created_at").eq("incident_id", id).order("created_at", { ascending: false }).limit(100),
  ]);
  if (assignedRows.error) throw new Error(`incident assignees: ${assignedRows.error.message}`);
  if (fixEvents.error) throw new Error(`incident fix history: ${fixEvents.error.message}`);
  const people = new Set<string>();
  for (const n of (notes.data ?? []) as Array<{ author_id: string | null }>) if (n.author_id) people.add(n.author_id);
  for (const n of (notifications.data ?? []) as Array<{ user_id: string }>) people.add(n.user_id);
  for (const a of (assignedRows.data ?? []) as Array<{ user_id: string }>) people.add(a.user_id);
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
  if (row.resolution?.actor_user_id && !names.has(row.resolution.actor_user_id)) {
    const { data: actor } = await admin.from("user_profiles").select("id, display_name, email").eq("id", row.resolution.actor_user_id).maybeSingle();
    if (actor) names.set(actor.id, actor.display_name || actor.email || actor.id.slice(0, 8));
  }
  const refs = [...new Set((row.timeline ?? []).map((t) => /^detection:([0-9a-f-]{36})$/i.exec(t.ref ?? "")?.[1]).filter((id): id is string => !!id && isUuid(id)))].slice(-100);
  let forensics: ReturnType<typeof forensicEvidence>[] = [];
  if (refs.length && row.server_id) {
    const { data, error } = await admin.from("detections")
      .select("id, server_id, rule_id, detected_at, source_ip, username, raw_metadata")
      .eq("organization_id", orgId).eq("server_id", row.server_id).in("id", refs);
    if (error) throw new Error(`incident evidence: ${error.message}`);
    forensics = ((data ?? []) as DetectionEvidence[]).map(forensicEvidence).map((e) => {
      // Old agents may have uploaded secrets. Omit any secret-bearing scalar before returning it.
      return Object.fromEntries(Object.entries(e).map(([k, v]) => [k, typeof v === "string" && findSecret({ [k]: v }) ? "[redacted secret material]" : v])) as ReturnType<typeof forensicEvidence>;
    });
  }
  const nameOf = (id: string | null) => (id ? names.get(id) ?? null : null);
  const memberById = new Map(members.map((m) => [m.user_id, m]));
  const assignees = ((assignedRows.data ?? []) as Array<{ user_id: string; assigned_at: string }>).map((a) => ({
    user_id: a.user_id,
    name: memberById.get(a.user_id)?.name ?? nameOf(a.user_id) ?? a.user_id.slice(0, 8),
    email: memberById.get(a.user_id)?.email ?? null,
    assigned_at: a.assigned_at,
  }));
  return {
    incident: { ...row, team_name: (team.data as { name?: string } | null)?.name ?? null, assignee_name: nameOf(row.assignee_id), assignees },
    role,
    forensics,
    resolution_actor_name: nameOf(row.resolution?.actor_user_id ?? null),
    members,
    fix_events: fixEvents.data ?? [],
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
  return ids.map((id) => ({ user_id: id, name: byId.get(id)?.display_name || byId.get(id)?.email || id.slice(0, 8), email: byId.get(id)?.email ?? null }));
}

export async function updateIncident(admin: SupabaseClient, p: Principal, orgId: string, id: string, body: Record<string, unknown>) {
  const { row } = await loadWithRole(admin, p, orgId, id, "write");
  const now = new Date().toISOString();
  const patch: Record<string, unknown> = {};
  if (body.status !== undefined && !isStatus(body.status)) throw new IncidentError(400, "status must be open, acknowledged or resolved");
  const actorLabel = p.kind === "agent" ? p.name : p.email || "team member";
  const actorUserId = p.kind === "user" ? p.userId : null;
  const actorAgentKeyId = p.kind === "agent" ? p.keyId : null;

  const fixInput = body.fix_work;
  if (fixInput !== undefined && (!fixInput || typeof fixInput !== "object" || Array.isArray(fixInput))) {
    throw new IncidentError(400, "fix_work must be an object");
  }
  const fixWork = (fixInput ?? {}) as Record<string, unknown>;
  for (const key of Object.keys(fixWork)) if (!FIX_WORK_FIELDS.has(key)) throw new IncidentError(400, `fix_work.${key} is not supported`);
  const fixPatch: Record<string, unknown> = {};
  const nextFix = {
    status: row.fix_status,
    pr_url: row.fix_pr_url,
    test_status: row.fix_test_status,
    test_summary: row.fix_test_summary,
    test_url: row.fix_test_url,
    verification: row.fix_verification,
    blocked_reason: row.fix_blocked_reason,
  } as Record<string, unknown>;
  const fixColumns: Record<string, string> = {
    status: "fix_status",
    pr_url: "fix_pr_url",
    test_status: "fix_test_status",
    test_summary: "fix_test_summary",
    test_url: "fix_test_url",
    verification: "fix_verification",
    blocked_reason: "fix_blocked_reason",
  };
  const fixChanges: Record<string, { from: unknown; to: unknown }> = {};
  for (const [key, value] of Object.entries(fixWork)) {
    if (key === "status") {
      if (typeof value !== "string" || !FIX_STATUSES.includes(value as FixStatus)) {
        throw new IncidentError(400, `fix_work.status must be one of ${FIX_STATUSES.join(", ")}`);
      }
      nextFix[key] = value;
    } else if (key === "test_status") {
      if (typeof value !== "string" || !FIX_TEST_STATUSES.includes(value as FixTestStatus)) {
        throw new IncidentError(400, `fix_work.test_status must be one of ${FIX_TEST_STATUSES.join(", ")}`);
      }
      nextFix[key] = value;
    } else {
      if (value !== null && typeof value !== "string") throw new IncidentError(400, `fix_work.${key} must be a string or null`);
      const textValue = typeof value === "string" ? value.trim() : null;
      const max = key === "test_summary" ? 4000 : 2000;
      if (textValue && textValue.length > max) throw new IncidentError(400, `fix_work.${key} is longer than ${max} characters`);
      if ((key === "pr_url" || key === "test_url") && textValue && !validHttpsUrl(textValue)) {
        throw new IncidentError(400, `fix_work.${key} must be a public https URL`);
      }
      if (textValue && findSecret({ [key]: textValue })) throw new IncidentError(422, "Fix progress must not contain secret material");
      nextFix[key] = textValue || null;
    }
  }
  if (Object.keys(fixWork).length) {
    if (nextFix.status === "blocked" && !(nextFix.blocked_reason as string | null)?.trim()) {
      throw new IncidentError(400, "A blocked incident needs fix_work.blocked_reason");
    }
    if (nextFix.status === "tested" && nextFix.test_status !== "passed") {
      throw new IncidentError(400, "Mark the fix tested only after fix_work.test_status is passed");
    }
    if (["passed", "failed", "skipped"].includes(String(nextFix.test_status)) && !(nextFix.test_summary as string | null)?.trim()) {
      throw new IncidentError(400, "Record a short fix_work.test_summary for passed, failed or skipped tests");
    }
    for (const [key, value] of Object.entries(nextFix)) {
      if (value !== (row as unknown as Record<string, unknown>)[fixColumns[key]]) {
        fixPatch[fixColumns[key]] = value;
        fixChanges[key] = { from: (row as unknown as Record<string, unknown>)[fixColumns[key]] ?? null, to: value };
      }
    }
    if (Object.keys(fixPatch).length) {
      patch.fix_updated_at = now;
      patch.fix_updated_by_user = actorUserId;
      patch.fix_updated_by_agent_key = actorAgentKeyId;
      Object.assign(patch, fixPatch);
    }
  }

  let requestedAssigneeIds: string[] | null = null;
  if (body.assignee_ids !== undefined && body.assignee_id !== undefined) {
    throw new IncidentError(400, "Pass assignee_ids or the legacy assignee_id, not both");
  }
  if (body.assignee_ids !== undefined) {
    if (!Array.isArray(body.assignee_ids) || body.assignee_ids.length > 50 || body.assignee_ids.some((x) => !isUuid(x))) {
      throw new IncidentError(400, "assignee_ids must be an array of at most 50 user UUIDs");
    }
    requestedAssigneeIds = [...new Set(body.assignee_ids as string[])];
  } else if (body.assignee_id !== undefined) {
    if (body.assignee_id === null) requestedAssigneeIds = [];
    else if (!isUuid(body.assignee_id)) throw new IncidentError(400, "assignee_id must be a uuid or null");
    else requestedAssigneeIds = [body.assignee_id];
  }
  let assigneeChanges: { added: Array<{ user_id: string; name: string; email: string | null }>; removed: Array<{ user_id: string; name: string; email: string | null }> } | null = null;
  let pendingAssigneeWrite: { stamped: Array<Record<string, unknown>>; removed: string[] } | null = null;
  if (requestedAssigneeIds !== null) {
    const members = await assignableMembers(admin, row);
    const memberById = new Map(members.map((m) => [m.user_id, m]));
    if (requestedAssigneeIds.some((userId) => !memberById.has(userId))) {
      throw new IncidentError(400, row.team_id ? "Every assignee must be on the incident's team" : "Every assignee must be a member of the org");
    }
    const { data: prior, error } = await admin.from("incident_fix_assignees").select("user_id").eq("incident_id", id);
    if (error) throw new Error(`incident assignees: ${error.message}`);
    const priorIds = ((prior ?? []) as Array<{ user_id: string }>).map((a) => a.user_id);
    const priorSet = new Set(priorIds);
    const requestedSet = new Set(requestedAssigneeIds);
    const added = requestedAssigneeIds.filter((userId) => !priorSet.has(userId));
    const removed = priorIds.filter((userId) => !requestedSet.has(userId));
    const stamped = requestedAssigneeIds.map((userId, index) => priorSet.has(userId)
      ? { incident_id: id, user_id: userId, sort_order: index }
      : {
        incident_id: id,
        user_id: userId,
        sort_order: index,
        assigned_by_user: actorUserId,
        assigned_by_agent_key: actorAgentKeyId,
        assigned_at: now,
      });
    pendingAssigneeWrite = { stamped, removed };
    patch.assignee_id = requestedAssigneeIds[0] ?? null;
    if (requestedAssigneeIds.length && nextFix.status === "unassigned") {
      nextFix.status = "assigned";
      patch.fix_status = "assigned";
      fixChanges.status = { from: row.fix_status, to: "assigned" };
    } else if (!requestedAssigneeIds.length && nextFix.status === "assigned") {
      nextFix.status = "unassigned";
      patch.fix_status = "unassigned";
      fixChanges.status = { from: row.fix_status, to: "unassigned" };
    }
    assigneeChanges = {
      added: added.map((user_id) => ({ user_id, name: memberById.get(user_id)!.name, email: memberById.get(user_id)!.email })),
      removed: removed.map((user_id) => ({ user_id, name: memberById.get(user_id)?.name ?? user_id.slice(0, 8), email: memberById.get(user_id)?.email ?? null })),
    };
    if (added.length || removed.length) {
      patch.fix_updated_at = now;
      patch.fix_updated_by_user = actorUserId;
      patch.fix_updated_by_agent_key = actorAgentKeyId;
    }
  }

  if (body.status !== undefined) {
    patch.status = body.status;
    if (body.status === "acknowledged") patch.acknowledged_at = row.acknowledged_at ?? now;
    if (body.status === "resolved" && row.status !== "resolved") {
      const finalFixStatus = (nextFix.status ?? row.fix_status) as FixStatus;
      const finalTestStatus = (nextFix.test_status ?? row.fix_test_status) as FixTestStatus;
      const verification = (nextFix.verification ?? row.fix_verification) as string | null;
      const closure = body.resolution;
      const closeFields = closure && typeof closure === "object" && !Array.isArray(closure) ? closure as Record<string, unknown> : {};
      if (finalFixStatus === "fixed" && (finalTestStatus !== "passed" || !verification?.trim())) {
        throw new IncidentError(409, "Before closing a fixed incident, record passing tests and fix_work.verification");
      }
      if (finalFixStatus !== "fixed" && finalFixStatus !== "false_positive") {
        throw new IncidentError(409, "Before closing, mark the fix fixed or false_positive and record verification");
      }
      if (!verification?.trim() && !(typeof closeFields.verification === "string" && closeFields.verification.trim())) {
        throw new IncidentError(409, "Record fix_work.verification before closing");
      }
      const r = body.resolution;
      if (!r || typeof r !== "object" || Array.isArray(r)) throw new IncidentError(400, "Record the resolution reason, action taken and verification before resolving");
      const input = r as Record<string, unknown>;
      const fields: Record<string, string> = {};
      for (const key of ["reason", "action", "verification"]) {
        if (typeof input[key] !== "string" || !input[key].trim() || input[key].length > 2000) throw new IncidentError(400, `resolution.${key} must be 1–2000 characters`);
        fields[key] = input[key].trim();
      }
      if (findSecret(fields)) throw new IncidentError(422, "Resolution must not contain secret material");
      if (finalFixStatus === "false_positive" && !verification?.trim()) {
        patch.fix_verification = fields.verification;
        patch.fix_updated_at = now;
        patch.fix_updated_by_user = actorUserId;
        patch.fix_updated_by_agent_key = actorAgentKeyId;
        fixChanges.verification = { from: null, to: fields.verification };
      }
      patch.resolved_at = now;
      patch.resolution = { ...fields, actor_user_id: actorUserId, actor_agent_key_id: actorAgentKeyId, at: now };
    }
    if (body.status === "open") patch.resolved_at = null;
    if (body.status === "open" && row.status === "resolved") {
      // Reopening must not collide with a newer live incident on the same key.
      const { data: clash } = await admin
        .from("incidents").select("id").eq("org_id", orgId).eq("dedupe_key", row.dedupe_key).neq("status", "resolved").neq("id", id).maybeSingle();
      if (clash) throw new IncidentError(409, "A newer open incident has the same key; work on that one");
    }
  }
  let note: string | null = null;
  if (body.note !== undefined) {
    if (typeof body.note !== "string" || !body.note.trim()) throw new IncidentError(400, "note must be a non-empty string");
    if (body.note.length > MAX_NOTE) throw new IncidentError(400, `note is longer than ${MAX_NOTE} characters`);
    note = body.note.trim();
    if (findSecret({ note })) throw new IncidentError(422, "Notes must not contain secret material");
  }
  if (!Object.keys(patch).length && note === null && requestedAssigneeIds === null && !Object.keys(fixWork).length) throw new IncidentError(400, "Nothing to change: pass status, assignee_ids, fix_work or note");

  if (pendingAssigneeWrite?.stamped.length) {
    const { error } = await admin.from("incident_fix_assignees").upsert(pendingAssigneeWrite.stamped, { onConflict: "incident_id,user_id" });
    if (error) throw new Error(`incident assignees: ${error.message}`);
  }
  if (pendingAssigneeWrite?.removed.length) {
    const { error } = await admin.from("incident_fix_assignees").delete().eq("incident_id", id).in("user_id", pendingAssigneeWrite.removed);
    if (error) throw new Error(`incident assignees: ${error.message}`);
  }

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
  if (assigneeChanges && (assigneeChanges.added.length || assigneeChanges.removed.length)) {
    const { error } = await admin.from("incident_fix_events").insert({
      incident_id: id,
      actor_user_id: actorUserId,
      actor_agent_key_id: actorAgentKeyId,
      actor_label: actorLabel,
      event_type: "assignees_changed",
      details: assigneeChanges,
      created_at: now,
    });
    if (error) throw new Error(`incident fix history: ${error.message}`);
  }
  if (Object.keys(fixChanges).length) {
    const { error } = await admin.from("incident_fix_events").insert({
      incident_id: id,
      actor_user_id: actorUserId,
      actor_agent_key_id: actorAgentKeyId,
      actor_label: actorLabel,
      event_type: "work_updated",
      details: { changes: fixChanges },
      created_at: now,
    });
    if (error) throw new Error(`incident fix history: ${error.message}`);
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
