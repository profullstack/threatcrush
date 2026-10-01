import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { loadFixReport, renderFixPrompt } from "@/lib/fix-report";

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const PRIVATE = {
  // Never indexed, never cached by a shared cache: the link is the credential.
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Cache-Control": "private, no-store",
};

// GET /r/<token> — an organization's public fix report, for an AI agent to
// read. Markdown by default (what agents read best); ?format=json for data.
export async function GET(req: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const notFound = () => new NextResponse("Not found\n", { status: 404, headers: { ...PRIVATE, "Content-Type": "text/plain; charset=utf-8" } });
  try {
    const { token } = await params;
    if (!TOKEN.test(token)) return notFound();

    const admin = getSupabaseAdmin();
    const { data: share } = await admin
      .from("report_shares")
      .select("id, org_id")
      .eq("token", token)
      .is("revoked_at", null)
      .maybeSingle();
    if (!share) return notFound();

    const report = await loadFixReport(admin, share.org_id);
    if (!report) return notFound();

    // Awaited: a supabase-js builder only runs when awaited.
    await admin.from("report_shares").update({ last_viewed_at: new Date().toISOString() }).eq("id", share.id);

    if (req.nextUrl.searchParams.get("format") === "json") {
      return NextResponse.json(report, { headers: PRIVATE });
    }
    return new NextResponse(renderFixPrompt(report), {
      headers: { ...PRIVATE, "Content-Type": "text/markdown; charset=utf-8" },
    });
  } catch (err) {
    console.error("Public report error:", err);
    return new NextResponse("Internal server error\n", { status: 500, headers: PRIVATE });
  }
}
