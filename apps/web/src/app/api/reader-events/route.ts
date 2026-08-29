import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * Engagement beacons from the on-site guide reader.
 *
 * Called with `navigator.sendBeacon` at scroll milestones and on page hide, so
 * it must stay cheap and must never fail loudly — a dropped beacon costs us one
 * analytics row, and there is nothing the reader could do about it anyway.
 */

const ALLOWED_SLUGS = new Set(["ctem-guide"]);
const MAX_SECTION_LEN = 80;

function clampPercent(v: unknown): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return 0;
  return Math.min(100, Math.max(0, Math.round(n)));
}

function clampSeconds(v: unknown): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return 0;
  // A day of "engagement" is a stuck timer, not a reader. Cap it at 4 hours.
  return Math.min(14_400, Math.max(0, Math.round(n)));
}

function str(v: unknown, max = 255): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  return s ? s.slice(0, max) : null;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    const sessionId = str(body.session_id, 64);
    if (!sessionId) {
      return NextResponse.json({ error: "session_id is required" }, { status: 400 });
    }

    const slug = str(body.slug, 64) ?? "ctem-guide";
    if (!ALLOWED_SLUGS.has(slug)) {
      return NextResponse.json({ error: "Unknown slug" }, { status: 400 });
    }

    const utm = body.utm && typeof body.utm === "object" ? body.utm : {};
    const supabase = getSupabaseAdmin();

    const { error } = await supabase.rpc("record_reader_progress", {
      p_session_id: sessionId,
      p_slug: slug,
      p_read_percent: clampPercent(body.read_percent),
      p_seconds_engaged: clampSeconds(body.seconds_engaged),
      p_furthest_section: str(body.furthest_section, MAX_SECTION_LEN),
      p_completed: body.completed === true,
      p_referrer: str(body.referrer, 500),
      p_utm_source: str(utm.utm_source, 120),
      p_utm_medium: str(utm.utm_medium, 120),
      p_utm_campaign: str(utm.utm_campaign, 120),
      p_utm_content: str(utm.utm_content, 120),
      p_utm_term: str(utm.utm_term, 120),
      p_ip_address: request.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? null,
      p_user_agent: request.headers.get("user-agent")?.slice(0, 500) ?? null,
    });

    if (error) {
      console.error("[reader-events] RPC error:", error);
      return NextResponse.json({ error: "Failed to record" }, { status: 500 });
    }

    // sendBeacon ignores the body; 204 keeps it off the wire.
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    console.error("[reader-events] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
