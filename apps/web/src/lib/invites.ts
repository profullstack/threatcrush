import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { hashSecret, newSecret, type TeamRole } from "@/lib/access";
import { appUrl, sendInviteEmail } from "@/lib/teams";

/**
 * Creating an invite, shared by "add a member" (when the account doesn't exist
 * yet) and the explicit invite buttons. A team invite carries a team role; an
 * org invite carries an org role. The token is returned once; only its hash is
 * stored. See supabase/migrations/*_org_invites.sql.
 */

export type OrgRole = "owner" | "admin" | "member" | "guest";

interface Common {
  orgId: string;
  email: string;
  invitedBy: string;
  inviterEmail: string | null;
  orgName: string;
}

export interface InviteResult {
  invite: { id: string; email: string; role: string; created_at: string; expires_at: string };
  url: string;
  emailed: boolean;
}

async function create(
  admin: SupabaseClient,
  row: Record<string, unknown>,
  dedupe: { column: "team_id" | "org_id_only"; value: string },
  email: Common & { teamName: string | null; role: TeamRole | OrgRole },
): Promise<InviteResult | null> {
  // One live invite per address in this scope: re-inviting replaces the link.
  let q = admin
    .from("team_invites")
    .update({ revoked_at: new Date().toISOString() })
    .eq("org_id", email.orgId)
    .eq("email", email.email)
    .is("accepted_at", null)
    .is("revoked_at", null);
  q = dedupe.column === "team_id" ? q.eq("team_id", dedupe.value) : q.is("team_id", null);
  await q;

  const token = newSecret();
  const { data: invite, error } = await admin
    .from("team_invites")
    .insert({ ...row, org_id: email.orgId, email: email.email, token_hash: hashSecret(token), invited_by: email.invitedBy })
    .select("id, email, role, org_role, created_at, expires_at")
    .single();
  if (error || !invite) {
    console.error("Create invite failed:", error);
    return null;
  }

  const url = `${appUrl()}/invite/${token}`;
  const emailed = await sendInviteEmail({
    to: email.email,
    orgName: email.orgName,
    teamName: email.teamName,
    role: email.role,
    inviter: email.inviterEmail,
    url,
  });
  return {
    invite: {
      id: invite.id,
      email: invite.email,
      // role defaults to 'read' in the table; an org invite's real role is org_role.
      role: (row.team_id ? invite.role : invite.org_role) as string,
      created_at: invite.created_at,
      expires_at: invite.expires_at,
    },
    url,
    emailed,
  };
}

export function createTeamInvite(
  admin: SupabaseClient,
  opts: Common & { teamId: string; teamName: string; role: TeamRole },
): Promise<InviteResult | null> {
  return create(admin, { team_id: opts.teamId, role: opts.role }, { column: "team_id", value: opts.teamId }, opts);
}

export function createOrgInvite(
  admin: SupabaseClient,
  opts: Common & { role: OrgRole },
): Promise<InviteResult | null> {
  // No team for an org invite: teamName null gives the "join the org" copy.
  return create(admin, { org_role: opts.role }, { column: "org_id_only", value: opts.orgId }, { ...opts, teamName: null });
}
