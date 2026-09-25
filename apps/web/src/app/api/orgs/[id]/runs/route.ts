import { NextRequest, NextResponse } from "next/server";
import { getAdminClient, getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { parsePaginationParam } from "@/lib/pagination";

const RUN_STATUSES = ["queued", "running", "succeeded", "failed", "cancelled"];

// `output` and `findings` are left out: they can be megabytes per run, and a
// feed only needs the summary. The per-run route still returns them.
const RUN_COLUMNS =
  "id, property_id, type, status, trigger, source, queued_at, started_at, completed_at, " +
  "findings_count, severity_summary, summary, error, properties(name, kind, target)";

type RunRow = Record<string, unknown> & { properties?: unknown };

// GET /api/orgs/[id]/runs — recent scan/pentest runs across every property in the org
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const { id: orgId } = await params;
    const admin = getAdminClient();

    const { data: membership } = await admin
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", auth.userId)
      .maybeSingle();
    if (!membership) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

    const url = new URL(req.url);
    const status = url.searchParams.get("status");
    if (status && !RUN_STATUSES.includes(status)) {
      return NextResponse.json({ error: "Invalid status" }, { status: 400 });
    }
    const limit = parsePaginationParam(url.searchParams.get("limit"), 25, { min: 1, max: 100 });
    const offset = parsePaginationParam(url.searchParams.get("offset"), 0);

    let query = admin
      .from("property_runs")
      .select(RUN_COLUMNS, { count: "exact" })
      .eq("org_id", orgId)
      .order("queued_at", { ascending: false })
      .range(offset, offset + limit - 1);
    if (status) query = query.eq("status", status);

    const { data, error, count } = await query;
    if (error) {
      console.error("List org runs error:", error);
      return NextResponse.json({ error: "Failed to list runs" }, { status: 500 });
    }

    const runs = ((data ?? []) as unknown as RunRow[]).map(({ properties, ...run }) => ({
      ...run,
      property: properties ?? null,
    }));

    return NextResponse.json({ runs, total: count ?? 0 });
  } catch (err) {
    console.error("List org runs error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
