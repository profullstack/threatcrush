import { NextResponse, type NextRequest } from "next/server";
import { takeLookupShared } from "@/lib/reputation";
import { reputationCaller, type ReputationCaller } from "@/lib/reputation-auth";
import { lookupIndicator, parseIndicator } from "@/lib/reputation-service";
import { feedPrincipal } from "@/lib/feed-auth";
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
];

const CREDIT_TOOLS = new Set(["redeem_credit_code", "list_invites", "create_invite"]);

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
          "IP and domain reputation from the ThreatCrush community threat database. Use reputation_lookup for one indicator, reputation_bulk for many. Needs a ThreatCrush API key as a Bearer token; keyless public lookups are at nichedb.dev/mcp.",
      });
    case "notifications/initialized":
      return null;
    case "ping":
      return ok(id, {});
    case "tools/list":
      return ok(id, { tools: TOOLS });
    case "tools/call": {
      const toolName = String(msg.params?.name ?? "");
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
