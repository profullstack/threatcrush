"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, listServers, type Server } from "@/lib/organizations";
import CreateOrgModal from "@/components/CreateOrgModal";
import Link from "next/link";

interface Organization {
  id: string;
  name: string;
  slug: string;
  user_role: string;
  created_at: string;
}

export default function OrgDetailContent({ slug }: { slug: string }) {
  const router = useRouter();
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [servers, setServers] = useState<Server[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!signedIn || authLoading) return;

    async function fetchData() {
      try {
        const { organizations: orgs } = await listOrganizations();
        const typedOrgs = orgs as unknown as Organization[];
        const found = typedOrgs.find((o) => o.slug === slug);
        if (!found) {
          setError("Organization not found");
          setLoading(false);
          return;
        }
        setOrg(found);

        const { servers: srvs } = await listServers(found.id);
        setServers(srvs as unknown as Server[]);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load organization");
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [signedIn, authLoading, slug]);

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
          <p className="text-zinc-400 mb-6">{error || "This organization doesn't exist or you don't have access."}</p>
          <Link href="/dashboard" className="text-green-500 hover:underline">
            ← Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <div className="flex items-center gap-3">
              <Link href="/dashboard" className="text-zinc-500 hover:text-zinc-300 transition-colors">
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
              </Link>
              <div>
                <h1 className="text-2xl font-bold text-white">{org.name}</h1>
                <p className="text-sm text-zinc-500">/{org.slug}</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href={`/org/${org.slug}/settings`}
              className="rounded-lg px-4 py-2 text-sm font-medium text-zinc-300 bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 transition-colors"
            >
              Settings
            </Link>
            <button
              onClick={() => setShowCreateOrg(true)}
              className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 transition-colors"
            >
              New Org
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-4 mb-8 sm:grid-cols-4">
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <p className="text-sm text-zinc-500">Servers</p>
            <p className="text-2xl font-bold text-white mt-1">{servers.length}</p>
          </div>
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <p className="text-sm text-zinc-500">Online</p>
            <p className="text-2xl font-bold text-green-400 mt-1">
              {servers.filter((s) => s.status === "online").length}
            </p>
          </div>
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <p className="text-sm text-zinc-500">Offline</p>
            <p className="text-2xl font-bold text-zinc-400 mt-1">
              {servers.filter((s) => s.status === "offline").length}
            </p>
          </div>
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <p className="text-sm text-zinc-500">Role</p>
            <p className="text-2xl font-bold text-white mt-1 capitalize">{org.user_role}</p>
          </div>
        </div>

        {/* Servers */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Servers</h2>
            {["owner", "admin"].includes(org.user_role) && (
              <Link
                href={`/org/${org.slug}/servers/new`}
                className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 transition-colors"
              >
                Add Server
              </Link>
            )}
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
                Register a server running threatcrushd to start seeing telemetry in the web dashboard.
              </p>
              <p className="mt-4 text-xs text-zinc-500">
                For real-time management (modules, logs, commands), use the Desktop or CLI.
              </p>
              {["owner", "admin"].includes(org.user_role) && (
                <div className="mt-6">
                  <Link
                    href={`/org/${org.slug}/servers/new`}
                    className="inline-flex items-center rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 transition-colors"
                  >
                    Add Server
                  </Link>
                </div>
              )}
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {servers.map((server) => (
                <ServerCard key={server.id} server={server} orgSlug={org.slug} />
              ))}
            </div>
          )}
        </div>

        {/* Web limitations callout */}
        <div className="mt-8 rounded-lg bg-blue-500/5 border border-blue-500/20 p-5">
          <div className="flex gap-3">
            <svg className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h3 className="text-sm font-medium text-blue-300">Web Dashboard Limitations</h3>
              <p className="text-sm text-blue-400/70 mt-1">
                The web app shows server status and telemetry pushed to our API. For full control —
                tailing logs live, managing modules, running scans — use the Desktop app or CLI,
                which connect via SSH using your <code className="bg-blue-500/10 px-1 rounded">~/.ssh</code> keys.
              </p>
              <div className="mt-3 flex flex-wrap gap-3">
                <a
                  href="/releases"
                  className="inline-flex items-center rounded-md px-3 py-1.5 text-xs font-medium text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 transition-colors"
                >
                  Download Desktop
                </a>
                <code className="inline-flex items-center rounded-md px-3 py-1.5 text-xs font-mono text-blue-300 bg-blue-500/10">
                  threatcrush connect
                </code>
              </div>
            </div>
          </div>
        </div>
      </div>

      <CreateOrgModal
        isOpen={showCreateOrg}
        onClose={() => setShowCreateOrg(false)}
        onSuccess={(newOrg) => router.push(`/org/${newOrg.slug}`)}
      />
    </div>
  );
}

function ServerCard({ server, orgSlug }: { server: Server; orgSlug: string }) {
  return (
    <Link
      href={`/org/${orgSlug}/servers/${server.id}`}
      className="block rounded-lg bg-zinc-900 border border-zinc-800 p-5 hover:border-zinc-700 transition-colors"
    >
      <div className="flex items-start justify-between">
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-medium text-white truncate">{server.name}</h3>
          <p className="text-sm text-zinc-500 mt-1">
            {server.hostname || server.ip_address}:{server.port}
          </p>
        </div>
        <StatusBadge status={server.status} />
      </div>

      <div className="mt-4 flex items-center justify-between text-xs text-zinc-500">
        <span>
          {server.last_seen ? `Last seen ${timeAgo(server.last_seen)}` : "Never seen"}
        </span>
        {server.threatcrushd_version && (
          <span className="font-mono">{server.threatcrushd_version}</span>
        )}
      </div>

      {server.ssh_username && (
        <p className="mt-2 text-xs text-zinc-600">
          SSH: {server.ssh_username}@
        </p>
      )}
    </Link>
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

  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
