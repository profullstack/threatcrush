import "server-only";
import type { NextRequest } from "next/server";
import { getPrincipal, type Principal } from "./access";
import { getSupabaseAdmin } from "./supabase";

/**
 * Resolve the caller of a key-gated feed. The full blocklist is corroborated
 * attacker addresses — a free ThreatCrush API key (`tc_agent_…`) is the gate,
 * the same scheme the daemon uses to submit. For firewall tooling that cannot
 * set an Authorization header easily, `?key=` and `X-API-Key` are accepted and
 * normalised into the Bearer form `access.ts` expects.
 */
export async function feedPrincipal(req: NextRequest): Promise<Principal | null> {
  let token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "").trim();
  if (!token) {
    token =
      req.headers.get("x-api-key")?.trim() ||
      new URL(req.url).searchParams.get("key")?.trim() ||
      undefined;
  }
  const shimmed = token ? new Request(req.url, { headers: { authorization: `Bearer ${token}` } }) : req;
  return getPrincipal(shimmed as unknown as NextRequest, getSupabaseAdmin());
}
