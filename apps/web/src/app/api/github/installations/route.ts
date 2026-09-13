import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, getAdminClient, unauthorized } from "@/lib/api-auth";
import { resetOpenThreatCache } from "@/lib/open-threats";
import { managesInstallation, type ManagedInstallation } from "@/lib/github-announce";

export const runtime = "nodejs";

/**
 * The GitHub App installations a signed-in person may manage, and the one
 * setting on them: whether findings from the installation's PUBLIC
 * repositories are announced on /discovery (OpenThreat). The gate is
 * `managesInstallation` in lib/github-announce.ts.
 */

const SELECT =
  "installation_id, account_login, account_type, sender_login, repository_selection, status, announce, installed_at";
const SELECT_NO_ANNOUNCE =
  "installation_id, account_login, account_type, sender_login, repository_selection, status, installed_at";

type Row = {
  installation_id: number;
  account_login: string | null;
  account_type: string | null;
  sender_login: string | null;
  repository_selection: string | null;
  status: string;
  announce?: boolean | null;
  installed_at: string | null;
};

async function listMine(login: string): Promise<{ rows: Row[]; announceColumn: boolean }> {
  const admin = getAdminClient();
  const filter = `account_login.ilike.${login},sender_login.ilike.${login}`;
  const first = await admin.from("github_installations").select(SELECT).or(filter);
  if (!first.error) return { rows: (first.data ?? []) as Row[], announceColumn: true };
  if (first.error.code === "42P01") return { rows: [], announceColumn: false };
  const second = await admin.from("github_installations").select(SELECT_NO_ANNOUNCE).or(filter);
  if (second.error) throw new Error(second.error.message);
  return { rows: (second.data ?? []) as Row[], announceColumn: false };
}

function publicView(row: Row): ManagedInstallation {
  return {
    installation_id: row.installation_id,
    account_login: row.account_login,
    account_type: row.account_type,
    repository_selection: row.repository_selection,
    status: row.status,
    announce: row.announce !== false,
    installed_at: row.installed_at,
  };
}

export async function GET(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();
  if (!user.githubLogin) {
    return NextResponse.json({ githubLogin: null, installations: [], announceColumn: true });
  }

  try {
    const { rows, announceColumn } = await listMine(user.githubLogin);
    const installations = rows
      .filter((row) => managesInstallation(user.githubLogin, row))
      .map(publicView);
    return NextResponse.json({ githubLogin: user.githubLogin, installations, announceColumn });
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}

export async function PATCH(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();
  if (!user.githubLogin) {
    return NextResponse.json({ error: "Sign in with GitHub to manage installations" }, { status: 403 });
  }

  const body = (await request.json().catch(() => null)) as
    | { installation_id?: unknown; announce?: unknown }
    | null;
  const installationId = Number(body?.installation_id);
  if (!body || !Number.isInteger(installationId) || installationId <= 0 || typeof body.announce !== "boolean") {
    return NextResponse.json(
      { error: "installation_id (integer) and announce (boolean) are required" },
      { status: 400 }
    );
  }

  const admin = getAdminClient();
  const found = await admin
    .from("github_installations")
    .select("installation_id, account_login, sender_login")
    .eq("installation_id", installationId)
    .maybeSingle();
  if (found.error) return NextResponse.json({ error: found.error.message }, { status: 500 });
  if (!found.data || !managesInstallation(user.githubLogin, found.data)) {
    // Not found and not yours read the same, so a login cannot probe for installation ids.
    return NextResponse.json({ error: "Installation not found" }, { status: 404 });
  }

  const updated = await admin
    .from("github_installations")
    .update({ announce: body.announce, updated_at: new Date().toISOString() })
    .eq("installation_id", installationId)
    .select(SELECT)
    .single();
  if (updated.error) {
    if (updated.error.code === "42703") {
      return NextResponse.json(
        { error: "The announce setting is not available yet on this deployment" },
        { status: 503 }
      );
    }
    return NextResponse.json({ error: updated.error.message }, { status: 500 });
  }

  resetOpenThreatCache();
  return NextResponse.json({ installation: publicView(updated.data as Row) });
}
