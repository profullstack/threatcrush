import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient } from "@/lib/supabase";
import { clearSignupGrantCookie } from "@/lib/signup-grant";

export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get("authorization")?.replace("Bearer ", "");
    if (token) {
      const supabase = getSupabaseClient();
      // Revoke the token server-side
      await supabase.auth.admin?.signOut?.(token).catch(() => {});
    }
    // Drop any pending signup grant too, so logging out on a shared machine
    // does not leave a usable identity behind.
    return clearSignupGrantCookie(NextResponse.json({ ok: true }));
  } catch {
    return clearSignupGrantCookie(NextResponse.json({ ok: true }));
  }
}
