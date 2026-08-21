import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";

/**
 * Admin view of the GitHub App's installations and the scans they triggered.
 *
 * Companion to /api/admin/marketplace, which covers billing. This covers the
 * product: who installed the app, and what the scanner found.
 *
 * Findings are deliberately not returned in the list. A single scan can carry
 * 500 of them, and 50 scans of that size is a payload nobody wants rendered in
 * a panel — pass ?scan=<id> for one scan's findings.
 */
export async function GET(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  const supabase = getSupabaseAdmin();
  const scanId = new URL(req.url).searchParams.get("scan");

  // Whether scanning can run at all. Both halves are needed, and reporting
  // "configured" on one of them is how you end up debugging the wrong thing.
  const configured = Boolean(
    process.env.GITHUB_APP_ID?.trim() && process.env.GITHUB_APP_PRIVATE_KEY?.trim()
  );

  if (scanId) {
    const { data, error } = await supabase
      .from("github_repo_scans")
      .select("id, full_name, ref, commit_sha, trigger, status, error, findings, truncated, truncation_reason, started_at, finished_at")
      .eq("id", scanId)
      .single();

    if (error?.code === "42P01") {
      return NextResponse.json({ configured, migrationApplied: false, scan: null });
    }
    if (error) {
      return NextResponse.json({ error: "Failed to load scan" }, { status: 404 });
    }
    return NextResponse.json({ configured, migrationApplied: true, scan: data });
  }

  const [installations, scans] = await Promise.all([
    supabase
      .from("github_installations")
      .select(
        "id, installation_id, account_login, account_type, repository_selection, status, permissions, installed_at, updated_at"
      )
      .order("updated_at", { ascending: false })
      .limit(200),
    supabase
      .from("github_repo_scans")
      .select(
        "id, installation_id, full_name, ref, commit_sha, trigger, status, error, files_considered, files_scanned, findings_count, peak_severity, truncated, truncation_reason, started_at, finished_at"
      )
      .order("started_at", { ascending: false })
      .limit(50),
  ]);

  // A missing table is the expected state until the migration is applied by
  // hand — no CI applies them here — so say so rather than returning a bare 500.
  if (installations.error?.code === "42P01" || scans.error?.code === "42P01") {
    return NextResponse.json({
      configured,
      migrationApplied: false,
      installations: [],
      scans: [],
    });
  }

  if (installations.error || scans.error) {
    return NextResponse.json({ error: "Failed to load GitHub App data" }, { status: 500 });
  }

  return NextResponse.json({
    configured,
    migrationApplied: true,
    installations: installations.data ?? [],
    scans: scans.data ?? [],
  });
}
