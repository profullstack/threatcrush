import "server-only";
import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin, getSupabaseClient } from "@/lib/supabase";

export type AuthenticatedRequest = {
  userId: string;
  email: string | null;
  /** The GitHub login behind a GitHub sign-in, or null for every other provider. */
  githubLogin: string | null;
};

export async function getAuthenticatedRequestUser(
  request: NextRequest,
): Promise<AuthenticatedRequest | null> {
  const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return null;

  const supabase = getSupabaseClient();
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return null;

  const meta = (user.user_metadata ?? {}) as Record<string, unknown>;
  const login = meta.user_name ?? meta.preferred_username;

  return {
    userId: user.id,
    email: user.email ?? null,
    githubLogin: typeof login === "string" && login.trim() ? login.trim() : null,
  };
}

export function unauthorized(message = "Not authenticated") {
  return NextResponse.json({ error: message }, { status: 401 });
}

export function getAdminClient() {
  return getSupabaseAdmin();
}
