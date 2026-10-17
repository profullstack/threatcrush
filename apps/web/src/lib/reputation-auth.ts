import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { NextRequest } from "next/server";
import type { Principal } from "./access";
import { feedPrincipal } from "./feed-auth";
import { readingOrgFor, tierFor, type ReputationTier } from "./reputation";
import { getSupabaseAdmin } from "./supabase";

export interface ReputationCaller {
  admin: SupabaseClient;
  principal: Principal;
  orgId: string | null;
  tier: ReputationTier;
  /** The allowance bucket: the org when there is one, else the key or user. */
  caller: string;
}

/**
 * Who is asking, which org pays, and which tier they get. Any ThreatCrush key
 * (Bearer, X-API-Key or ?key=) or a signed-in session; `?org=` (or `org` in
 * a JSON body, passed as `requestedOrg`) picks the org for a user.
 */
export async function reputationCaller(req: NextRequest, requestedOrg?: string | null): Promise<ReputationCaller | null> {
  const principal = await feedPrincipal(req);
  if (!principal) return null;
  const admin = getSupabaseAdmin();
  const orgId = await readingOrgFor(admin, principal, requestedOrg ?? new URL(req.url).searchParams.get("org"));
  const tier = await tierFor(admin, orgId);
  const caller = orgId ?? (principal.kind === "agent" ? principal.keyId : principal.userId);
  return { admin, principal, orgId, tier, caller };
}

export function allowanceHeaders(tier: ReputationTier, a: { limit: number; remaining: number }): Record<string, string> {
  return {
    "x-reputation-tier": tier,
    "x-ratelimit-limit": String(a.limit),
    "x-ratelimit-remaining": String(a.remaining),
    "cache-control": "private, no-store",
  };
}

export const KEY_REQUIRED =
  "A ThreatCrush API key is required. Create one free at threatcrush.com; keyless lookups are at nichedb.dev/reputation.";
