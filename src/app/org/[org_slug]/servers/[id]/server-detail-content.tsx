"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, getServer, deleteServer, type Server } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
import Link from "next/link";

interface ThreatEvent {
  id: string;
  timestamp: string;
  module: string;
  category: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  message: string;
  source_ip?: string;
}

export default function ServerDetailContent({ orgSlug, serverId }: { orgSlug: string; serverId: string }) {
  const router = useRouter();
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<{ id: string; name: string; slug: string; user_role: string } | null>(null);
  const [server, setServer] = useState<Server | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Live events feed
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [eventsError, setEventsError] = useState("");
  const [liveMode, setLiveMode] = useState(true);
  const eventsEndRef = useRef<HTMLDivElement>(null);

  // Fetch events with polling
  const fetchEvents = useCallback(async () => {
    if (!signedIn) return;
    try {
      const res = await fetch(`/api/servers/${serverId}/events`, { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json() as { events: ThreatEvent[] };
        setEvents(data.events || []);
        setEventsError("");
      } else {
        // API returns empty for now since no events table exists yet
        setEvents([]);
      }
    } catch {
      // Don't show error for polling — just stop loading
    } finally {
      setEventsLoading(false);
    }
  }, [signedIn, serverId]);

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

  // Poll events every 5s when live mode is on
  useEffect(() => {
    if (!signedIn) return;
    fetchEvents();
    if (!liveMode) return;
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, [signedIn, liveMode, fetchEvents]);

  // Auto-scroll to bottom on new events
  useEffect(() => {
    if (liveMode && eventsEndRef.current) {
      eventsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events, liveMode]);

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
              <dd className="mt-1"><StatusBadge status={server.status} /></dd>
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
                    href="/releases"
                    className="inline-block mt-2 text-xs font-medium text-green-400 hover:text-green-300 underline"
                  >
                    Download Desktop →
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ─── Live Events Feed ─── */}
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Threat Events</h2>
            <button
              onClick={() => setLiveMode(!liveMode)}
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                liveMode
                  ? "bg-green-500/10 text-green-400 hover:bg-green-500/20"
                  : "bg-zinc-700 text-zinc-400 hover:bg-zinc-600"
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${liveMode ? "bg-green-400 animate-pulse" : "bg-zinc-500"}`} />
              {liveMode ? "Live" : "Paused"}
            </button>
          </div>

          {eventsLoading ? (
            <div className="text-center py-8">
              <p className="text-sm text-zinc-500">Loading events...</p>
            </div>
          ) : events.length === 0 ? (
            <div className="text-center py-8">
              <svg className="mx-auto h-10 w-10 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <p className="mt-3 text-sm text-zinc-500">
                No events yet. Events will appear here when threatcrushd pushes telemetry to the API.
              </p>
              <p className="mt-1 text-xs text-zinc-600">
                The web app tails the event log from Supabase — no SSH needed.
              </p>
            </div>
          ) : (
            <div className="rounded-md bg-black/40 p-4 font-mono text-sm max-h-96 overflow-y-auto space-y-2">
              {events.map((event, i) => (
                <div key={event.id || i} className="flex items-start gap-3">
                  <span className="text-zinc-600 flex-shrink-0">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                  <SeverityBadge severity={event.severity} />
                  {event.module && (
                    <span className="text-zinc-500 flex-shrink-0">[{event.module}]</span>
                  )}
                  <span className="text-zinc-200 break-all">{event.message}</span>
                  {event.source_ip && (
                    <span className="text-zinc-500 flex-shrink-0 text-xs">{event.source_ip}</span>
                  )}
                </div>
              ))}
              <div ref={eventsEndRef} />
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
