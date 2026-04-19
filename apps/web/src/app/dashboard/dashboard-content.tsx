"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, listServers, type Server } from "@/lib/organizations";
import OrgOnboarding from "@/components/OrgOnboarding";
import CreateOrgModal from "@/components/CreateOrgModal";
import Link from "next/link";

interface Organization {
  id: string;
  name: string;
  slug: string;
  user_role: string;
  created_at: string;
}

export default function DashboardContent() {
  const { signedIn, loading: authLoading, currentOrgId, setCurrentOrgId } = useAuth();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [servers, setServers] = useState<Server[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [error, setError] = useState("");

  const handleOrgCreated = async (org: Record<string, unknown>) => {
    const orgId = org.id as string;
    await setCurrentOrgId(orgId);
    setOrganizations(prev => [...prev, { ...org, user_role: "owner" } as Organization]);
    setServers([]);
    setShowCreateOrg(false);
  };

  useEffect(() => {
    if (!signedIn || authLoading) return;

    async function fetchData() {
      try {
        const { organizations: orgs } = await listOrganizations();
        const typedOrgs = orgs as unknown as Organization[];
        setOrganizations(typedOrgs);

        // If user has a current org, fetch its servers
        if (currentOrgId) {
          const org = typedOrgs.find((o) => o.id === currentOrgId);
          if (org) {
            const { servers: srvs } = await listServers(org.id);
            setServers(srvs as unknown as Server[]);
          }
        } else if (typedOrgs.length > 0) {
          // Use first org
          const { servers: srvs } = await listServers(typedOrgs[0].id);
          setServers(srvs as unknown as Server[]);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load data");
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [signedIn, authLoading, currentOrgId]);

  if (authLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading...</div>
      </div>
    );
  }

  if (!signedIn) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-white mb-2">Sign In Required</h1>
          <p className="text-zinc-400">
            Please <Link href="/auth/login" className="text-green-500 hover:underline">sign in</Link> to access your dashboard.
          </p>
        </div>
      </div>
    );
  }

  // If no organizations, show onboarding
  if (organizations.length === 0) {
    return <OrgOnboarding />;
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white">Dashboard</h1>
            <p className="text-zinc-400 mt-1">
              Manage your organizations and servers
            </p>
          </div>
          <div className="flex items-center gap-3">
            {/* Org switcher */}
            {organizations.length > 1 && (
              <select
                value={currentOrgId || ""}
                onChange={async (e) => {
                  const orgId = e.target.value || null;
                  if (orgId) {
                    await setCurrentOrgId(orgId);
                    const { servers: srvs } = await listServers(orgId);
                    setServers(srvs as unknown as Server[]);
                  }
                }}
                className="rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-sm text-white focus:border-green-500 focus:outline-none"
              >
                {organizations.map((org) => (
                  <option key={org.id} value={org.id}>{org.name}</option>
                ))}
              </select>
            )}
            <button
              onClick={() => setShowCreateOrg(true)}
              className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 transition-colors"
            >
              New Organization
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Organizations */}
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-white mb-4">Your Organizations</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {organizations.map((org) => (
              <Link
                key={org.id}
                href={`/org/${org.slug}`}
                className="block rounded-lg bg-zinc-900 border border-zinc-800 p-5 hover:border-zinc-700 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-base font-medium text-white">{org.name}</h3>
                    <p className="text-sm text-zinc-500 mt-1">{org.slug}</p>
                  </div>
                  <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                    org.user_role === "owner"
                      ? "bg-green-500/10 text-green-400"
                      : org.user_role === "admin"
                        ? "bg-blue-500/10 text-blue-400"
                        : "bg-zinc-700 text-zinc-400"
                  }`}>
                    {org.user_role}
                  </span>
                </div>
                <p className="text-xs text-zinc-500 mt-3">
                  Created {new Date(org.created_at).toLocaleDateString()}
                </p>
              </Link>
            ))}
          </div>
        </div>

        {/* Servers (from current org or first org) */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">
              Servers {currentOrgId && organizations.find(o => o.id === currentOrgId) ? `— ${organizations.find(o => o.id === currentOrgId)?.name}` : ""}
            </h2>
            <Link
              href={currentOrgId
                ? `/org/${organizations.find(o => o.id === currentOrgId)?.slug || organizations[0].slug}/servers/new`
                : `/org/${organizations[0].slug}/servers/new`
              }
              className="rounded-lg px-3 py-1.5 text-sm font-medium text-zinc-300 bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 transition-colors"
            >
              Add Server
            </Link>
          </div>

          {servers.length === 0 ? (
            <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-8 text-center">
              <svg
                className="mx-auto h-12 w-12 text-zinc-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
                />
              </svg>
              <h3 className="mt-4 text-sm font-medium text-white">No servers yet</h3>
              <p className="mt-2 text-sm text-zinc-400">
                Add your first ThreatCrushd server to start monitoring.
              </p>
              <div className="mt-6">
                <Link
                  href={currentOrgId
                    ? `/org/${organizations.find(o => o.id === currentOrgId)?.slug || organizations[0].slug}/servers/new`
                    : `/org/${organizations[0].slug}/servers/new`
                  }
                  className="inline-flex items-center rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 transition-colors"
                >
                  Add Server
                </Link>
              </div>
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-zinc-800">
              <table className="min-w-full divide-y divide-zinc-800">
                <thead className="bg-zinc-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                      Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                      Host
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                      Last Seen
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                      Version
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-zinc-950 divide-y divide-zinc-800">
                  {servers.map((server) => {
                    const currentOrg = organizations.find(o => o.id === currentOrgId) || organizations[0];
                    return (
                    <tr key={server.id} className="hover:bg-zinc-900 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <Link href={`/org/${currentOrg.slug}/servers/${server.id}`} className="text-sm font-medium text-white hover:text-green-400">
                          {server.name}
                        </Link>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-zinc-300">
                          {server.hostname || server.ip_address}
                        </div>
                        <div className="text-xs text-zinc-500">
                          :{server.port}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <StatusBadge status={server.status} />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-zinc-400">
                        {server.last_seen ? timeAgo(server.last_seen) : "Never"}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-zinc-400">
                        {server.threatcrushd_version || "—"}
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <CreateOrgModal
        isOpen={showCreateOrg}
        onClose={() => setShowCreateOrg(false)}
        onSuccess={handleOrgCreated}
      />
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    online: "bg-green-500/10 text-green-400",
    offline: "bg-zinc-700 text-zinc-400",
    unreachable: "bg-red-500/10 text-red-400",
  };

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${styles[status] || styles.offline}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${
        status === "online" ? "bg-green-400" : status === "unreachable" ? "bg-red-400" : "bg-zinc-500"
      }`} />
      {status}
    </span>
  );
}

function timeAgo(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
