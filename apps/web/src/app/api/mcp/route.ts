import { NextResponse, type NextRequest } from "next/server";
import { takeLookupShared } from "@/lib/reputation";
import { reputationCaller, type ReputationCaller } from "@/lib/reputation-auth";
import { lookupIndicator, parseIndicator } from "@/lib/reputation-service";
import { feedPrincipal } from "@/lib/feed-auth";
import { atLeast, findingsRoleOf, type Principal } from "@/lib/access";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getFinding, listFindings, triageFindings, TriageError } from "@/lib/scan-findings";
import { getIncident, IncidentError, listIncidents, pageable, raiseIncident, updateIncident } from "@/lib/incidents/store";
import { notifyIncident } from "@/lib/incidents/notify";
import { WebhookError } from "@profullstack/webhooks";
import { getHooks } from "@/lib/webhooks/hub";
import { webhookOrgFor } from "@/lib/webhooks/owner";
import {
  createInvite,
  inviteOverview,
  InviteError,
  inviteUrl,
  originFromHeaders,
  redeemCreditCode,
  settleInvitesSentBy,
} from "@/lib/credit-codes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * The ThreatCrush MCP server at /api/mcp: stateless Streamable HTTP, JSON
 * responses, POST only. Tools need a ThreatCrush key (Authorization: Bearer
 * tc_agent_…); tools/list does not, so a client can discover them first.
 * Pro orgs get the Pro fields, the same as the REST API.
 */

const PROTOCOL = "2025-06-18";
const MAX_BULK = { free: 100, pro: 1000 } as const;

const TOOLS = [
  {
    name: "reputation_lookup",
    description:
      "Look up an IP address or a domain against the ThreatCrush community threat database (what every linked ThreatCrush daemon blocked). Returns `listed` (the corroboration bar: independent reporters agree), a 0-100 `score`, severity, reports, reporters, rules and country; a domain is answered from its A/AAAA addresses plus nichedb.dev's public answer (abuse.ch, SURBL). With Reputation Pro: 90 days of history, the /24 neighbourhood, the network owner (ASN) and how much of it is listed, city and the reasons behind the score. Registered servers, allowlisted addresses and anyone who logged in are never reported.",
    inputSchema: {
      type: "object",
      properties: { indicator: { type: "string", description: "An IP address or a domain" } },
      required: ["indicator"],
    },
  },
  {
    name: "reputation_bulk",
    description:
      "Look up many IPs or domains at once (up to 100 with a free key, 1,000 with Reputation Pro). Results come back in request order; each counts against the daily allowance.",
    inputSchema: {
      type: "object",
      properties: { indicators: { type: "array", items: { type: "string" } } },
      required: ["indicators"],
    },
  },
  {
    name: "redeem_credit_code",
    description:
      "Redeem a ThreatCrush credit code (CR-XXXX-XXXX-XXXX-XXXX) into the signed-in account's credit balance (1 credit = $1.00). Needs the account's session token (`threatcrush login`), not a tc_agent_ key: agent keys belong to a team, not a person.",
    inputSchema: {
      type: "object",
      properties: { code: { type: "string", description: "The credit code" } },
      required: ["code"],
    },
  },
  {
    name: "list_invites",
    description: "The signed-in account's invites: how many are left of 3, who joined, and whether the bonus credits were paid. Session token only.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "create_invite",
    description:
      "Create one invite link (each account has 3, single use, 30 days). When a new account joins on it and confirms its email, both get bonus credits. Session token only.",
    inputSchema: { type: "object", properties: { note: { type: "string", description: "Who it is for (only you see it)" } } },
  },
  {
    name: "findings_list",
    description:
      "Your org's tracked findings from threatcrush scan, pentest and ai-scan (deduped across runs, with a triage status). Default: open + acknowledged. Session token or tc_agent_ key.",
    inputSchema: {
      type: "object",
      properties: {
        org_id: { type: "string", description: "Organization id (default: the key's org, or your first org)" },
        status: { type: "string", description: "Comma list of open, acknowledged, fixed, false_positive, ignored, or all" },
        severity: { type: "string", description: "Comma list of critical, high, medium, low, info" },
        source: { type: "string", description: "Comma list of scan, pentest, ai-scan" },
        limit: { type: "number", description: "Max 500, default 100" },
      },
    },
  },
  {
    name: "findings_get",
    description: "One tracked finding with its details (code snippet, remediation, evidence), property and history.",
    inputSchema: { type: "object", properties: { org_id: { type: "string" }, id: { type: "string", description: "Finding id" } }, required: ["id"] },
  },
  {
    name: "findings_triage",
    description:
      "Set the status and/or note of up to 500 findings: acknowledged, fixed, false_positive, ignored or open. fixed is reopened by a later run that still sees it; false_positive and ignored never are. Needs write.",
    inputSchema: {
      type: "object",
      properties: {
        org_id: { type: "string" },
        ids: { type: "array", items: { type: "string" } },
        status: { type: "string", enum: ["open", "acknowledged", "fixed", "false_positive", "ignored"] },
        note: { type: "string", description: "Why (shown everywhere the finding is)" },
      },
      required: ["ids"],
    },
  },
  {
    name: "incidents_list",
    description:
      "Your org's incidents: what `threatcrush investigate --raise`, the daemon (critical detections) and people raised to humans. Only the teams you can see. Session token or tc_agent_ key.",
    inputSchema: {
      type: "object",
      properties: {
        org_id: { type: "string", description: "Organization id (default: the key's org, or your first org)" },
        status: { type: "string", description: "Comma list of open, acknowledged, resolved, or all (default all)" },
        team_id: { type: "string" },
        limit: { type: "number", description: "Max 500, default 100" },
      },
    },
  },
  {
    name: "incidents_get",
    description: "One incident: linked forensic evidence, multi-person assignees, fix and test progress, work history, recorded resolution/operator, findings, timeline, notes and who was paged.",
    inputSchema: { type: "object", properties: { org_id: { type: "string" }, id: { type: "string", description: "Incident id" } }, required: ["id"] },
  },
  {
    name: "incidents_update",
    description: "Update fix work performed by your assigned agent or human: set multiple assignees, fix status, PR URL, test status and evidence, verification or blocker, and/or add a note. ThreatCrush catalogs the incident and does not execute remediation. Closing requires status fixed with passing tests and verification, or false_positive with a reason and verification, plus resolution.reason/action/verification. Needs write.",
    inputSchema: {
      type: "object",
      properties: {
        org_id: { type: "string" },
        id: { type: "string" },
        status: { type: "string", enum: ["open", "acknowledged", "resolved"] },
        assignee_id: { type: ["string", "null"] },
        assignee_ids: { type: "array", maxItems: 50, items: { type: "string", format: "uuid" }, description: "Replace the assignee list with these active org/team member user IDs; [] clears it. An assignee receives write access to this incident. Use incidents_get to find member IDs and emails." },
        note: { type: "string" },
        fix_work: {
          type: "object", additionalProperties: false,
          properties: {
            status: { type: "string", enum: ["unassigned", "assigned", "in_progress", "blocked", "pr_open", "testing", "tested", "fixed", "false_positive"] },
            pr_url: { type: ["string", "null"], format: "uri", description: "HTTPS URL to the remediation PR" },
            test_status: { type: "string", enum: ["not_run", "running", "passed", "failed", "skipped"] },
            test_summary: { type: ["string", "null"], maxLength: 4000 },
            test_url: { type: ["string", "null"], format: "uri", description: "HTTPS URL to the CI run or test report" },
            verification: { type: ["string", "null"], maxLength: 2000 },
            blocked_reason: { type: ["string", "null"], maxLength: 2000 },
          },
        },
        resolution: {
          type: "object", additionalProperties: false,
          properties: {
            reason: { type: "string", minLength: 1, maxLength: 2000 },
            action: { type: "string", minLength: 1, maxLength: 2000 },
            verification: { type: "string", minLength: 1, maxLength: 2000 },
          },
          required: ["reason", "action", "verification"],
        },
      },
      required: ["id"],
    },
  },
  {
    name: "incidents_raise",
    description:
      "Raise an incident report (report_version 1: title, severity, source, dedupe_key, summary, verdict, findings, timeline, recommendations, optional team_id/server_id). The same dedupe_key while open updates it; a new incident pages the team by SMS and email once. Reports that contain anything shaped like a private key or mnemonic are refused. Needs write.",
    inputSchema: {
      type: "object",
      properties: {
        org_id: { type: "string" },
        report: { type: "object", description: "The report body, as POST /api/orgs/{id}/incidents takes it" },
      },
      required: ["report"],
    },
  },
  {
    name: "webhooks_list",
    description:
      "Your org's webhook endpoints (signed Standard Webhooks deliveries, retried for about three days) and the events ThreatCrush emits: detection.created, findings.raised, reputation.changed. Endpoints behind a Webhook alert destination follow your alert rules; the others get every event they subscribe to. Org owner/admin session token or an admin tc_agent_ key.",
    inputSchema: { type: "object", properties: { org_id: { type: "string" } } },
  },
  {
    name: "webhooks_create",
    description: "Add a webhook endpoint (public https URL). Returns the endpoint and its signing secret (whsec_…), shown once.",
    inputSchema: {
      type: "object",
      properties: {
        org_id: { type: "string" },
        url: { type: "string" },
        events: { type: "array", items: { type: "string" }, description: "Event patterns: *, detection.created, findings.*, ... (default *)" },
        description: { type: "string" },
      },
      required: ["url"],
    },
  },
  {
    name: "webhooks_update",
    description: "Change a webhook endpoint's url, events, description, or switch it on/off (on again clears its failure count).",
    inputSchema: {
      type: "object",
      properties: {
        org_id: { type: "string" },
        id: { type: "string" },
        url: { type: "string" },
        events: { type: "array", items: { type: "string" } },
        description: { type: "string" },
        enabled: { type: "boolean" },
      },
      required: ["id"],
    },
  },
  {
    name: "webhooks_delete",
    description: "Remove a webhook endpoint and its delivery log.",
    inputSchema: { type: "object", properties: { org_id: { type: "string" }, id: { type: "string" } }, required: ["id"] },
  },
  {
    name: "webhooks_test",
    description: "Send a signed webhook.test event to one endpoint now and say how it went.",
    inputSchema: { type: "object", properties: { org_id: { type: "string" }, id: { type: "string" } }, required: ["id"] },
  },
  {
    name: "webhooks_rotate_secret",
    description: "Replace an endpoint's signing secret; the old one stops working at once. Returns the new secret.",
    inputSchema: { type: "object", properties: { org_id: { type: "string" }, id: { type: "string" } }, required: ["id"] },
  },
  {
    name: "webhooks_deliveries",
    description: "Recent webhook deliveries (status, attempts, last HTTP status/error, payload), for one endpoint or all.",
    inputSchema: {
      type: "object",
      properties: { org_id: { type: "string" }, id: { type: "string", description: "Endpoint id (optional)" }, limit: { type: "number" } },
    },
  },
];

const WEBHOOK_TOOLS = new Set(["webhooks_list", "webhooks_create", "webhooks_update", "webhooks_delete", "webhooks_test", "webhooks_rotate_secret", "webhooks_deliveries"]);

async function callWebhookTool(req: NextRequest, name: string, args: Record<string, unknown>) {
  const p = await feedPrincipal(req);
  if (!p) return text("Sign in first: pass your ThreatCrush session token (`threatcrush login`) or an admin tc_agent_ key as the Bearer token.", true);
  const who = await webhookOrgFor(getSupabaseAdmin(), p, typeof args.org_id === "string" ? args.org_id : null);
  if ("error" in who) return text(who.error, true);
  const hooks = getHooks();
  const id = String(args.id ?? "");
  try {
    if (name === "webhooks_list") return text({ endpoints: await hooks.listEndpoints(who.orgId), event_types: hooks.eventTypes });
    if (name === "webhooks_create") {
      return text(await hooks.createEndpoint(who.orgId, {
        url: String(args.url ?? ""),
        events: Array.isArray(args.events) ? args.events.map(String) : undefined,
        description: typeof args.description === "string" ? args.description : undefined,
      }));
    }
    if (name === "webhooks_update") {
      const { org_id: _o, id: _i, ...patch } = args;
      return text(await hooks.updateEndpoint(who.orgId, id, patch as Parameters<typeof hooks.updateEndpoint>[2]));
    }
    if (name === "webhooks_delete") return text(await hooks.deleteEndpoint(who.orgId, id));
    if (name === "webhooks_test") return text(await hooks.test(who.orgId, id));
    if (name === "webhooks_rotate_secret") return text(await hooks.rotateSecret(who.orgId, id));
    return text({ deliveries: await hooks.deliveries(who.orgId, { endpointId: id || undefined, limit: Number(args.limit) || 50 }) });
  } catch (err) {
    if (err instanceof WebhookError) return text(err.message, true);
    console.error("[mcp] webhook tool failed", (err as Error).message);
    return text("That did not work. Try again.", true);
  }
}

const CREDIT_TOOLS = new Set(["redeem_credit_code", "list_invites", "create_invite"]);
const FINDING_TOOLS = new Set(["findings_list", "findings_get", "findings_triage"]);
const INCIDENT_TOOLS = new Set(["incidents_list", "incidents_get", "incidents_update", "incidents_raise"]);

async function callIncidentTool(req: NextRequest, name: string, args: Record<string, unknown>) {
  const p = await feedPrincipal(req);
  if (!p) return text("Sign in first: pass your ThreatCrush session token (`threatcrush login`) or a tc_agent_ key as the Bearer token.", true);
  const admin = getSupabaseAdmin();
  const orgId = await findingsOrg(p, args.org_id);
  if (!orgId) return text("No organization: pass org_id, or create one at threatcrush.com.", true);
  try {
    if (name === "incidents_list") return text(await listIncidents(admin, p, orgId, args));
    if (name === "incidents_get") return text(await getIncident(admin, p, orgId, String(args.id ?? "")));
    if (name === "incidents_update") {
      const { org_id: _o, id, ...body } = args;
      return text(await updateIncident(admin, p, orgId, String(id ?? ""), body));
    }
    const out = await raiseIncident(admin, p, orgId, args.report);
    const notified = out.page ? await notifyIncident(pageable(out.incident), admin) : null;
    return text({ incident: out.incident, created: out.created, paged: out.page, notified });
  } catch (err) {
    if (err instanceof IncidentError) return text(err.message, true);
    console.error("[mcp] incident tool failed", (err as Error).message);
    return text("That did not work. Try again.", true);
  }
}

/** The org a findings tool acts on: the one asked for, else the agent key's, else the person's first. */
async function findingsOrg(p: Principal, asked: unknown): Promise<string | null> {
  if (typeof asked === "string" && asked) return asked;
  if (p.kind === "agent") return p.orgId;
  const { data } = await getSupabaseAdmin().from("organization_members").select("org_id").eq("user_id", p.userId).order("joined_at", { ascending: true }).limit(1);
  return data?.[0]?.org_id ?? null;
}

async function callFindingsTool(req: NextRequest, name: string, args: Record<string, unknown>) {
  const p = await feedPrincipal(req);
  if (!p) return text("Sign in first: pass your ThreatCrush session token (`threatcrush login`) or a tc_agent_ key as the Bearer token.", true);
  const admin = getSupabaseAdmin();
  const orgId = await findingsOrg(p, args.org_id);
  if (!orgId) return text("No organization: pass org_id, or create one at threatcrush.com.", true);
  const role = await findingsRoleOf(admin, p, orgId);
  if (!atLeast(role, name === "findings_triage" ? "write" : "read")) return text("Not allowed on that organization.", true);
  try {
    if (name === "findings_list") return text(await listFindings(admin, orgId, args));
    if (name === "findings_get") {
      const f = await getFinding(admin, orgId, String(args.id ?? ""));
      return f ? text(f) : text("No such finding in that organization.", true);
    }
    return text({ updated: await triageFindings(admin, orgId, { userId: p.kind === "user" ? p.userId : null }, args) });
  } catch (err) {
    if (err instanceof TriageError) return text(err.message, true);
    console.error("[mcp] findings tool failed", err);
    return text("That did not work. Try again.", true);
  }
}

type Rpc = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };

const ok = (id: Rpc["id"], result: unknown) => ({ jsonrpc: "2.0", id: id ?? null, result });
const fail = (id: Rpc["id"], code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
const text = (value: unknown, isError = false) => ({
  content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }],
  ...(isError ? { isError: true } : {}),
});

async function callTool(who: ReputationCaller, name: string, args: Record<string, unknown>) {
  if (name === "reputation_lookup") {
    const ind = parseIndicator(String(args.indicator ?? ""));
    if (!ind) return text("indicator must be a public IP address or a domain", true);
    const a = await takeLookupShared(who.admin, who.caller, who.tier);
    if (!a.ok) return text(`The ${a.limit} lookups a day on this key are used.`, true);
    return text(await lookupIndicator(who.admin, ind, who.tier));
  }
  if (name === "reputation_bulk") {
    const list = Array.isArray(args.indicators) ? args.indicators.map(String) : [];
    if (!list.length) return text("indicators must be a non-empty array", true);
    if (list.length > MAX_BULK[who.tier]) return text(`At most ${MAX_BULK[who.tier]} indicators per call.`, true);
    const parsed = list.map((raw) => ({ raw, ind: parseIndicator(raw) }));
    const a = await takeLookupShared(who.admin, who.caller, who.tier, parsed.filter((p) => p.ind).length);
    if (!a.ok) return text(`That would exceed the ${a.limit} lookups a day on this key.`, true);
    const results = [];
    for (const p of parsed) {
      results.push(p.ind ? await lookupIndicator(who.admin, p.ind, who.tier) : { query: p.raw, error: "not an IP or a domain" });
    }
    return text({ count: results.length, results });
  }
  return null;
}

async function callCreditTool(req: NextRequest, name: string, args: Record<string, unknown>) {
  const p = await feedPrincipal(req);
  if (!p) return text("Sign in first: pass your ThreatCrush session token (`threatcrush login`) as the Bearer token.", true);
  if (p.kind !== "user") return text("Credit codes and invites belong to a person: use a session token, not a tc_agent_ key.", true);
  try {
    if (name === "redeem_credit_code") {
      const r = await redeemCreditCode(p.userId, String(args.code ?? ""));
      return r.ok ? text({ ok: true, credits: r.credits, balance_usd: r.balance }) : text(r.message, true);
    }
    if (name === "list_invites") {
      await settleInvitesSentBy(p.userId);
      return text(await inviteOverview(p.userId));
    }
    const inv = await createInvite(p.userId, String(args.note ?? ""));
    return text({ code: inv.code, url: inviteUrl(originFromHeaders(req.headers), inv.code), expiresAt: inv.expiresAt });
  } catch (err) {
    if (err instanceof InviteError) return text(err.message, true);
    console.error("[mcp] credit tool failed", err);
    return text("That did not work. Try again.", true);
  }
}

async function handle(req: NextRequest, msg: Rpc) {
  const id = msg.id;
  const isNotification = id === undefined;
  switch (msg.method) {
    case "initialize":
      return ok(id, {
        protocolVersion: PROTOCOL,
        capabilities: { tools: {} },
        serverInfo: { name: "ThreatCrush", version: "0.13" },
        instructions:
          "IP and domain reputation from the ThreatCrush community threat database (reputation_lookup, reputation_bulk), your org's tracked scan/pentest/ai-scan findings (findings_list, findings_get, findings_triage), incidents raised to your team (incidents_list, incidents_get, incidents_update, incidents_raise), and your org's webhook endpoints (webhooks_list, webhooks_create, webhooks_update, webhooks_delete, webhooks_test, webhooks_rotate_secret, webhooks_deliveries). Needs a ThreatCrush API key as a Bearer token; keyless public lookups are at nichedb.dev/mcp.",
      });
    case "notifications/initialized":
      return null;
    case "ping":
      return ok(id, {});
    case "tools/list":
      return ok(id, { tools: TOOLS });
    case "tools/call": {
      const toolName = String(msg.params?.name ?? "");
      if (FINDING_TOOLS.has(toolName)) {
        return ok(id, await callFindingsTool(req, toolName, (msg.params?.arguments as Record<string, unknown>) ?? {}));
      }
      if (INCIDENT_TOOLS.has(toolName)) {
        return ok(id, await callIncidentTool(req, toolName, (msg.params?.arguments as Record<string, unknown>) ?? {}));
      }
      if (WEBHOOK_TOOLS.has(toolName)) {
        return ok(id, await callWebhookTool(req, toolName, (msg.params?.arguments as Record<string, unknown>) ?? {}));
      }
      if (CREDIT_TOOLS.has(toolName)) {
        return ok(id, await callCreditTool(req, toolName, (msg.params?.arguments as Record<string, unknown>) ?? {}));
      }
      const who = await reputationCaller(req);
      if (!who) return ok(id, text("A ThreatCrush API key is required (Authorization: Bearer tc_agent_…). Create one free at threatcrush.com.", true));
      const name = String(msg.params?.name ?? "");
      const result = await callTool(who, name, (msg.params?.arguments as Record<string, unknown>) ?? {});
      return result ? ok(id, result) : fail(id, -32602, `Unknown tool: ${name}`);
    }
    default:
      return isNotification ? null : fail(id, -32601, `Method not found: ${msg.method}`);
  }
}

export async function POST(req: NextRequest) {
  let payload: Rpc | Rpc[];
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json(fail(null, -32700, "Invalid JSON"), { status: 400 });
  }
  const headers = { "mcp-protocol-version": PROTOCOL, "cache-control": "no-store" };
  if (Array.isArray(payload)) {
    const answers = (await Promise.all(payload.map((m) => handle(req, m)))).filter(Boolean);
    return answers.length ? NextResponse.json(answers, { headers }) : new NextResponse(null, { status: 202, headers });
  }
  const answer = await handle(req, payload);
  return answer ? NextResponse.json(answer, { headers }) : new NextResponse(null, { status: 202, headers });
}

export function GET() {
  return NextResponse.json(fail(null, -32601, "This MCP server is stateless: POST JSON-RPC to /api/mcp"), {
    status: 405,
    headers: { allow: "POST" },
  });
}
