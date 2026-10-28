import { NextResponse, type NextRequest } from "next/server";
import { webhooksApi } from "@profullstack/webhooks";
import { feedPrincipal } from "@/lib/feed-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getHooks } from "@/lib/webhooks/hub";
import { webhookOrgFor } from "@/lib/webhooks/owner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * /api/v1/webhooks: the @profullstack/webhooks API for an organization.
 * Auth: a tc_agent_ key with the admin role (Bearer or X-API-Key), or a
 * session token of an org owner/admin with ?org_id= (or X-Org-Id).
 *
 *   GET    /                      endpoints + event_types
 *   POST   /                      { url, events?, description? } -> { endpoint, secret }
 *   GET|PATCH|DELETE /:id
 *   GET    /:id/secret            POST /:id/rotate      POST /:id/test
 *   GET    /:id/deliveries        GET /deliveries       POST /deliveries/:id/retry
 *
 * Endpoints behind a Webhook alert destination are listed here too; alert
 * rules decide what reaches those. The others get every event they subscribe to.
 */
async function handle(req: NextRequest): Promise<Response> {
  const p = await feedPrincipal(req);
  if (!p) return NextResponse.json({ error: "Not authenticated: send a tc_agent_ key or a session token" }, { status: 401 });
  const asked = new URL(req.url).searchParams.get("org_id") || req.headers.get("x-org-id");
  const who = await webhookOrgFor(getSupabaseAdmin(), p, asked);
  if ("error" in who) return NextResponse.json({ error: who.error }, { status: who.status });

  const api = webhooksApi(getHooks(), { basePath: "/api/v1/webhooks", owner: () => who.orgId });
  try {
    return (await api(req)) ?? NextResponse.json({ error: "Not found" }, { status: 404 });
  } catch (err) {
    console.error("[webhooks api]", (err as Error).message);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export const GET = handle;
export const POST = handle;
export const PATCH = handle;
export const PUT = handle;
export const DELETE = handle;
