"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, getServer, deleteServer, type Server } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
import { serverConnectionState } from "@/lib/server-status";
import { useVisiblePolling } from "@/lib/use-visible-polling";
import ConnectServerHint from "@/components/ConnectServerHint";
import Link from "next/link";

interface Detection {
  id: string;
  rule_id: string | null;
  severity: string;
  title: string;
  source_ip: string | null;
  detected_at: string;
  last_detected_at: string | null;
  occurrences: number | null;
  status: string;
}

export default function ServerDetailContent({ orgSlug, serverId }: { orgSlug: string; serverId: string }) {
  const router = useRouter();
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<{ id: string; name: string; slug: string; user_role: string } | null>(null);
  const [server, setServer] = useState<Server | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [detections, setDetections] = useState<Detection[]>([]);
  const [detectionsLoading, setDetectionsLoading] = useState(true);

  const orgId = org?.id;
  const refresh = useCallback(async () => {
    if (!orgId) return;
    try {
      const [detRes, { server: srv }] = await Promise.all([
        fetch(`/api/orgs/${orgId}/servers/${serverId}/detections?limit=20`, { headers: authHeaders() }),
        getServer(orgId, serverId),
      ]);
      if (detRes.ok) {
        const data = await detRes.json() as { detections: Detection[] };
        setDetections(data.detections || []);
      }
      setServer(srv as unknown as Server);
    } catch {
      // Polling failures are transient; keep the last good data.
    } finally {
      setDetectionsLoading(false);
    }
  }, [orgId, serverId]);

  // Initial server + org fetch
  useEffect(() => {
    if (!signedIn || authLoading) return;

    async function fetchData() {
      try {
        const { organizations: orgs } = await listOrganizations();
        const typedOrgs = orgs as unknown as Array<{ id: string; name: string; slug: string; user_role: string }>;
        const found = typedOrgs.find((o) => o.slug === orgSlug);
        if (!found) {
          setError("Organization not found");
          setLoading(false);
          return;
        }
        setOrg(found);

        const { server: srv } = await getServer(found.id, serverId);
        setServer(srv as unknown as Server);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load server");
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [signedIn, authLoading, orgSlug, serverId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Detections and last_seen (online/offline) refresh while the tab is visible.
  useVisiblePolling(refresh, 30_000, !!orgId);

  const handleDelete = async () => {
    if (!org || !server) return;
    if (!confirm(`Are you sure you want to remove "${server.name}"? This cannot be undone.`)) return;

    try {
      await deleteServer(org.id, server.id);
      router.push(`/org/${org.slug}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete server");
    }
  };

  if (authLoading || loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading...</div>
      </div>
    );
  }

  if (!org || !server) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center max-w-md px-4">
          <h1 className="text-xl font-bold text-white mb-2">Server Not Found</h1>
          <p className="text-zinc-400 mb-6">{error || "This server doesn't exist or you don't have access."}</p>
          <Link href={`/org/${orgSlug}`} className="text-green-500 hover:underline">
            ← Back to Organization
          </Link>
        </div>
      </div>
    );
  }

  const canManage = ["owner", "admin"].includes(org.user_role);

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Breadcrumb + Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Link href={`/org/${org.slug}`} className="text-zinc-500 hover:text-zinc-300 transition-colors">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">{server.name}</h1>
              <p className="text-sm text-zinc-500">
                {server.hostname || server.ip_address}:{server.port}
              </p>
            </div>
          </div>
          {canManage && (
            <button
              onClick={handleDelete}
              className="rounded-lg px-4 py-2 text-sm font-medium text-red-400 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-colors"
            >
              Remove Server
            </button>
          )}
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Status Card */}
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-6 mb-8">
          <h2 className="text-lg font-semibold text-white mb-4">Server Details</h2>
          <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-sm text-zinc-500">Status</dt>
              <dd className="mt-1"><StatusBadge status={serverConnectionState(server.last_seen)} /></dd>
            </div>
            <div>
              <dt className="text-sm text-zinc-500">Last Seen</dt>
              <dd className="mt-1 text-sm text-white">
                {server.last_seen ? timeAgo(server.last_seen) : "Never"}
              </dd>
            </div>
            <div>
              <dt className="text-sm text-zinc-500">Hostname</dt>
              <dd className="mt-1 text-sm text-white font-mono">{server.hostname || "—"}</dd>
            </div>
            <div>
              <dt className="text-sm text-zinc-500">IP Address</dt>
              <dd className="mt-1 text-sm text-white font-mono">{server.ip_address || "—"}</dd>
            </div>
            <div>
              <dt className="text-sm text-zinc-500">SSH Port</dt>
              <dd className="mt-1 text-sm text-white font-mono">{server.port}</dd>
            </div>
            <div>
              <dt className="text-sm text-zinc-500">SSH Username</dt>
              <dd className="mt-1 text-sm text-white font-mono">{server.ssh_username || "—"}</dd>
            </div>
            <div>
              <dt className="text-sm text-zinc-500">threatcrushd Version</dt>
              <dd className="mt-1 text-sm text-white font-mono">{server.threatcrushd_version || "—"}</dd>
            </div>
            <div>
              <dt className="text-sm text-zinc-500">Added</dt>
              <dd className="mt-1 text-sm text-white">{new Date(server.created_at).toLocaleDateString()}</dd>
            </div>
          </dl>
        </div>

        {/* ─── Call-to-Action: Desktop/TUI ─── */}
        <div className="rounded-lg bg-green-500/5 border border-green-500/20 p-6 mb-8">
          <div className="flex items-start gap-4">
            <div className="flex-shrink-0">
              <svg className="h-8 w-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
            <div>
              <h3 className="text-base font-semibold text-green-300">Remote Server Management</h3>
              <p className="text-sm text-green-400/70 mt-1">
                The web app shows telemetry pushed to our API. For full control — running commands,
                managing modules, editing configs — use the Desktop app or CLI, which connect via
                SSH using your <code className="bg-green-500/10 px-1 rounded">~/.ssh</code> keys.
              </p>

              <div className="mt-4 space-y-3">
                {/* CLI */}
                <div className="rounded-md bg-black/30 p-3">
                  <p className="text-xs font-medium text-green-300 mb-1">CLI (TUI)</p>
                  <code className="text-sm text-green-400/90 font-mono">
                    threatcrush connect {server.hostname || server.ip_address}
                  </code>
                  <p className="text-xs text-green-400/50 mt-1">
                    Uses your ~/.ssh keys to connect
                  </p>
                </div>

                {/* Desktop */}
                <div className="rounded-md bg-black/30 p-3">
                  <p className="text-xs font-medium text-green-300 mb-1">Desktop App</p>
                  <p className="text-sm text-green-400/70">
                    Open the Desktop app and connect to this server for a full GUI experience.
                  </p>
                  <a
                    href="https://github.com/profullstack/threatcrush/releases/latest"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-block mt-2 text-xs font-medium text-green-400 hover:text-green-300 underline"
                  >
                    Download Desktop →
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ─── Recent Detections ─── */}
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Recent Detections</h2>
            <Link href={`/org/${org.slug}/detections`} className="text-xs text-zinc-400 hover:text-zinc-200">
              All detections →
            </Link>
          </div>

          {detectionsLoading ? (
            <div className="text-center py-8">
              <p className="text-sm text-zinc-500">Loading detections...</p>
            </div>
          ) : detections.length === 0 ? (
            <div className="text-center py-8">
              {server.last_seen ? (
                <p className="text-sm text-zinc-500">
                  No detections from this server yet. It last reported {timeAgo(server.last_seen)}.
                </p>
              ) : (
                <>
                  <p className="text-sm text-zinc-500 mb-6">
                    This server has never reported. Link its daemon to this organization:
                  </p>
                  <ConnectServerHint />
                </>
              )}
            </div>
          ) : (
            <div className="divide-y divide-zinc-800">
              {detections.map((d) => {
                const count = d.occurrences ?? 1;
                return (
                  <Link key={d.id} href={`/org/${org.slug}/detections?detection=${d.id}`}
                    className="flex items-start gap-3 py-2 hover:bg-zinc-800/40 transition-colors">
                    <span className="text-zinc-600 flex-shrink-0 text-xs font-mono mt-0.5">
                      {new Date(d.last_detected_at ?? d.detected_at).toLocaleString()}
                    </span>
                    <SeverityBadge severity={d.severity} />
                    <span className="text-zinc-200 text-sm break-all flex-1">{d.title}</span>
                    {count > 1 && <span className="text-xs text-zinc-300 flex-shrink-0">&times;{count}</span>}
                    {d.source_ip && (
                      <span className="text-zinc-500 flex-shrink-0 text-xs font-mono">{d.source_ip}</span>
                    )}
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      </div>
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
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-sm font-medium ${styles[status] || styles.offline}`}>
      <span className={`h-2 w-2 rounded-full ${
        status === "online" ? "bg-green-400" : status === "unreachable" ? "bg-red-400" : "bg-zinc-500"
      }`} />
      {status}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    info: "bg-blue-500/10 text-blue-400",
    low: "bg-yellow-500/10 text-yellow-400",
    medium: "bg-orange-500/10 text-orange-400",
    high: "bg-red-500/10 text-red-400",
    critical: "bg-red-500/20 text-red-300 border border-red-500/30",
  };

  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-bold uppercase flex-shrink-0 ${styles[severity] || styles.info}`}>
      {severity}
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
