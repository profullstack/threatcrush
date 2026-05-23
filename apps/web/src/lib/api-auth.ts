import "server-only";
import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin, getSupabaseClient } from "@/lib/supabase";

export type AuthenticatedRequest = {
  userId: string;
  email: string | null;
};

export async function getAuthenticatedRequestUser(
  request: NextRequest,
): Promise<AuthenticatedRequest | null> {
  const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return null;

  const supabase = getSupabaseClient();
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return null;

  return {
    userId: user.id,
    email: user.email ?? null,
  };
}

export function unauthorized(message = "Not authenticated") {
  return NextResponse.json({ error: message }, { status: 401 });
}

export function getAdminClient() {
  return getSupabaseAdmin();
}
