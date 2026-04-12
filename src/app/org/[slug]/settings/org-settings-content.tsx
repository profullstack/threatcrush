"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import {
  listOrganizations,
  updateOrganization,
  deleteOrganization,
  listMembers,
  addMember,
  updateMemberRole,
  removeMember,
} from "@/lib/organizations";
import Link from "next/link";

interface OrgData {
  id: string;
  name: string;
  slug: string;
  user_role: string;
}

interface MemberData {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
}

export default function OrgSettingsContent({ slug }: { slug: string }) {
  const router = useRouter();
  const { signedIn, loading: authLoading, profile } = useAuth();
  const [org, setOrg] = useState<OrgData | null>(null);
  const [members, setMembers] = useState<MemberData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Rename form
  const [renameName, setRenameName] = useState("");
  const [renaming, setRenaming] = useState(false);

  // Invite form
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviting, setInviting] = useState(false);

  // Delete confirmation
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");

  useEffect(() => {
    if (!signedIn || authLoading) return;

    async function fetchData() {
      try {
        const { organizations: orgs } = await listOrganizations();
        const typedOrgs = orgs as unknown as OrgData[];
        const found = typedOrgs.find((o) => o.slug === slug);
        if (!found) {
          setError("Organization not found");
          setLoading(false);
          return;
        }
        setOrg(found);
        setRenameName(found.name);

        const { members: mems } = await listMembers(found.id);
        setMembers(mems as unknown as MemberData[]);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load organization");
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [signedIn, authLoading, slug]);

  const handleRename = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!org) return;
    setRenaming(true);
    setError("");
    try {
      const { organization } = await updateOrganization(org.id, { name: renameName });
      setOrg({ ...org, name: organization.name as string, slug: organization.slug as string });
      setSuccess("Organization updated");
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update organization");
    } finally {
      setRenaming(false);
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!org) return;
    setInviting(true);
    setError("");
    try {
      const { member } = await addMember(org.id, inviteEmail, "member");
      setMembers([...members, member as unknown as MemberData]);
      setInviteEmail("");
      setSuccess("Member invited");
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to invite member");
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: string) => {
    if (!org) return;
    try {
      await updateMemberRole(org.id, userId, newRole);
      setMembers(members.map((m) => (m.id === userId ? { ...m, role: newRole } : m)));
      setSuccess("Role updated");
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update role");
    }
  };

  const handleRemoveMember = async (userId: string) => {
    if (!org) return;
    if (!confirm("Remove this member?")) return;
    try {
      await removeMember(org.id, userId);
      setMembers(members.filter((m) => m.id !== userId));
      setSuccess("Member removed");
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove member");
    }
  };

  const handleDeleteOrg = async () => {
    if (!org || deleteConfirmText !== org.name) return;
    setDeleting(true);
    setError("");
    try {
      await deleteOrganization(org.id);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete organization");
      setDeleting(false);
    }
  };

  if (authLoading || loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading...</div>
      </div>
    );
  }

  if (!org) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center max-w-md px-4">
          <h1 className="text-xl font-bold text-white mb-2">Organization Not Found</h1>
          <p className="text-zinc-400 mb-6">{error}</p>
          <Link href="/dashboard" className="text-green-500 hover:underline">
            ← Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  const isOwner = org.user_role === "owner";
  const isAdmin = ["owner", "admin"].includes(org.user_role);

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-3xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Breadcrumb */}
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <Link href={`/org/${org.slug}`} className="text-zinc-500 hover:text-zinc-300 transition-colors">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">{org.name} — Settings</h1>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}
        {success && (
          <div className="mb-6 rounded-lg bg-green-500/10 border border-green-500/20 px-4 py-3">
            <p className="text-sm text-green-400">{success}</p>
          </div>
        )}

        {/* General Settings */}
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4">General</h2>
          <form onSubmit={handleRename} className="flex gap-3">
            <div className="flex-1">
              <label htmlFor="org-name" className="sr-only">Organization name</label>
              <input
                id="org-name"
                type="text"
                value={renameName}
                onChange={(e) => setRenameName(e.target.value)}
                required
                disabled={!isAdmin}
                className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>
            <button
              type="submit"
              disabled={renaming || renameName === org.name || !isAdmin}
              className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {renaming ? "Saving..." : "Save"}
            </button>
          </form>
          {!isAdmin && (
            <p className="text-xs text-zinc-500 mt-2">Only owners and admins can edit organization settings.</p>
          )}
        </div>

        {/* Members */}
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4">Members ({members.length})</h2>

          {/* Invite form */}
          {isAdmin && (
            <form onSubmit={handleInvite} className="flex gap-3 mb-6">
              <div className="flex-1">
                <label htmlFor="invite-email" className="sr-only">Email address</label>
                <input
                  id="invite-email"
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="member@example.com"
                  required
                  className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500"
                />
              </div>
              <button
                type="submit"
                disabled={inviting || !inviteEmail}
                className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {inviting ? "Inviting..." : "Invite"}
              </button>
            </form>
          )}

          {/* Members list */}
          <div className="space-y-3">
            {members.map((member) => (
              <div key={member.id} className="flex items-center justify-between py-3 border-b border-zinc-800 last:border-0">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="h-8 w-8 rounded-full bg-zinc-700 flex items-center justify-center text-sm text-zinc-300 flex-shrink-0">
                    {(member.display_name || member.email).charAt(0).toUpperCase()}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm text-white truncate">
                      {member.display_name || member.email}
                    </p>
                    <p className="text-xs text-zinc-500 truncate">{member.email}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {isOwner && member.id !== profile?.id ? (
                    <select
                      value={member.role}
                      onChange={(e) => handleRoleChange(member.id, e.target.value)}
                      className="rounded-md bg-zinc-800 border border-zinc-700 px-2 py-1 text-xs text-white focus:border-green-500 focus:outline-none"
                    >
                      <option value="owner">Owner</option>
                      <option value="admin">Admin</option>
                      <option value="member">Member</option>
                    </select>
                  ) : (
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                      member.role === "owner" ? "bg-green-500/10 text-green-400"
                        : member.role === "admin" ? "bg-blue-500/10 text-blue-400"
                        : "bg-zinc-700 text-zinc-400"
                    }`}>
                      {member.role}
                    </span>
                  )}
                  {isAdmin && member.id !== profile?.id && (
                    <button
                      onClick={() => handleRemoveMember(member.id)}
                      className="text-zinc-500 hover:text-red-400 transition-colors"
                      aria-label="Remove member"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Danger Zone */}
        {isOwner && (
          <div className="rounded-lg bg-red-500/5 border border-red-500/20 p-6">
            <h2 className="text-lg font-semibold text-red-300 mb-2">Danger Zone</h2>
            <p className="text-sm text-red-400/70 mb-4">
              Deleting the organization will permanently remove all associated data, including
              servers and member associations. This cannot be undone.
            </p>

            {!showDeleteConfirm ? (
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="rounded-lg px-4 py-2 text-sm font-medium text-red-400 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-colors"
              >
                Delete Organization
              </button>
            ) : (
              <div className="space-y-3">
                <p className="text-sm text-red-300">
                  Type <strong className="text-white">"{org.name}"</strong> to confirm:
                </p>
                <div className="flex gap-3">
                  <input
                    type="text"
                    value={deleteConfirmText}
                    onChange={(e) => setDeleteConfirmText(e.target.value)}
                    placeholder={org.name}
                    className="flex-1 rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500"
                    autoFocus
                  />
                  <button
                    onClick={() => setShowDeleteConfirm(false)}
                    className="rounded-lg px-4 py-2 text-sm font-medium text-zinc-300 bg-zinc-800 hover:bg-zinc-700 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleDeleteOrg}
                    disabled={deleting || deleteConfirmText !== org.name}
                    className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-red-500 hover:bg-red-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {deleting ? "Deleting..." : "Delete"}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
