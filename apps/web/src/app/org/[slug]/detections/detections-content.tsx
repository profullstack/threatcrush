"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, listServers } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
import { useVisiblePolling } from "@/lib/use-visible-polling";
import ConnectServerHint from "@/components/ConnectServerHint";
import Link from "next/link";

interface Detection {
  id: string;
  server_id: string;
  rule_id: string | null;
  severity: string;
  title: string;
  description: string | null;
  source_ip: string | null;
  username: string | null;
  detected_at: string;
  last_detected_at: string | null;
  occurrences: number | null;
  status: string;
}

interface Organization {
  id: string;
  name: string;
  slug: string;
}

const REFRESH_MS = 30_000;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-green-500/20 text-green-400 border-green-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  new: "text-red-400",
  acknowledged: "text-yellow-400",
  resolved: "text-green-400",
};

export default function DetectionsContent({ slug, highlightId }: { slug: string; highlightId: string | null }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [servers, setServers] = useState<Record<string, string>>({});
  const [detections, setDetections] = useState<Detection[]>([]);
  const [pinned, setPinned] = useState<Detection | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const scrolledTo = useRef<string | null>(null);
  const limit = 25;

  const fetchDetections = useCallback(async (orgId: string) => {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    params.set("limit", String(limit));
    params.set("offset", String(page * limit));

    const res = await fetch(`/api/orgs/${orgId}/detections?${params}`, { headers: authHeaders() });
    if (res.ok) {
      const data = await res.json();
      setDetections(data.detections || []);
      setTotal(data.total || 0);
      setRefreshedAt(new Date());
    }
  }, [severity, status, page]);

  // A link from an alert (?detection=<id>) may point past the loaded page;
  // fetch that one detection so it can be pinned above the feed.
  const fetchPinned = useCallback(async (orgId: string) => {
    if (!highlightId) return;
    const res = await fetch(`/api/orgs/${orgId}/detections?id=${encodeURIComponent(highlightId)}`, {
      headers: authHeaders(),
    });
    if (res.ok) {
      const data = await res.json();
      setPinned((data.detections || [])[0] ?? null);
    }
  }, [highlightId]);

  useEffect(() => {
    if (!signedIn || authLoading) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find(o => o.slug === slug);
        if (!found) return;
        setOrg(found);
        const [{ servers: srvs }] = await Promise.all([
          listServers(found.id),
          fetchDetections(found.id),
          fetchPinned(found.id),
        ]);
        const map: Record<string, string> = {};
        for (const s of srvs as unknown as Array<{ id: string; name: string }>) map[s.id] = s.name;
        setServers(map);
      } catch { /* ignore */ }
      finally { setLoading(false); }
    })();
  }, [signedIn, authLoading, slug, fetchDetections, fetchPinned]);

  useVisiblePolling(() => {
    if (org) {
      fetchDetections(org.id);
      fetchPinned(org.id);
    }
  }, REFRESH_MS, !!org);

  const inList = !!highlightId && detections.some(d => d.id === highlightId);

  useEffect(() => {
    if (!highlightId || scrolledTo.current === highlightId) return;
    if (!inList && !pinned) return;
    const el = document.getElementById(`detection-${highlightId}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      scrolledTo.current = highlightId;
    }
  }, [highlightId, inList, pinned]);

  const updateStatus = async (ids: string[], newStatus: string) => {
    if (!org) return;
    await fetch(`/api/orgs/${org.id}/detections`, {
      method: "PATCH",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ ids, status: newStatus }),
    });
    await Promise.all([fetchDetections(org.id), fetchPinned(org.id)]);
  };

  if (authLoading || loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  }

  if (!org) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Organization not found</div></div>;
  }

  const filtered = severity !== "" || status !== "";
  const hasServers = Object.keys(servers).length > 0;

  const renderRow = (d: Detection) => {
    const highlighted = d.id === highlightId;
    const count = d.occurrences ?? 1;
    const lastSeen = d.last_detected_at ?? d.detected_at;
    return (
      <div key={d.id} id={`detection-${d.id}`}
        className={`rounded-lg bg-zinc-900 border p-4 transition-colors ${
          highlighted ? "border-green-500/60 ring-1 ring-green-500/40" : "border-zinc-800 hover:border-zinc-700"
        }`}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${SEVERITY_COLORS[d.severity] || SEVERITY_COLORS.info}`}>
                {d.severity.toUpperCase()}
              </span>
              {count > 1 && (
                <span className="inline-flex items-center rounded-md bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-xs font-medium text-zinc-200"
                  title={`Reported ${count} times`}>
                  &times;{count}
                </span>
              )}
              <span className={`text-xs ${STATUS_COLORS[d.status] || "text-zinc-400"}`}>
                {d.status}
              </span>
              {d.rule_id && <span className="text-xs text-zinc-600 font-mono">{d.rule_id}</span>}
            </div>
            <h3 className="text-white font-medium truncate">{d.title}</h3>
            {d.description && <p className="text-zinc-400 text-sm mt-1 line-clamp-2">{d.description}</p>}
            <div className="flex items-center gap-4 mt-2 text-xs text-zinc-500 flex-wrap">
              <span>
                <Link href={`/org/${slug}/servers/${d.server_id}`} className="text-zinc-400 hover:text-zinc-200">
                  {servers[d.server_id] || d.server_id.slice(0, 8)}
                </Link>
              </span>
              {d.source_ip && <span>IP: <code className="text-zinc-400">{d.source_ip}</code></span>}
              {d.username && <span>User: <code className="text-zinc-400">{d.username}</code></span>}
              <span>{count > 1 ? "First " : ""}{new Date(d.detected_at).toLocaleString()}</span>
              {count > 1 && <span>Last seen {new Date(lastSeen).toLocaleString()}</span>}
            </div>
          </div>
          <div className="flex gap-2 shrink-0">
            {d.status === "new" && (
              <button onClick={() => updateStatus([d.id], "acknowledged")}
                className="rounded px-3 py-1 text-xs bg-zinc-800 text-zinc-300 hover:bg-zinc-700 border border-zinc-700">
                Ack
              </button>
            )}
            {d.status !== "resolved" && (
              <button onClick={() => updateStatus([d.id], "resolved")}
                className="rounded px-3 py-1 text-xs bg-zinc-800 text-green-400 hover:bg-zinc-700 border border-zinc-700">
                Resolve
              </button>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Link href={`/org/${slug}`} className="text-zinc-500 hover:text-zinc-300">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">Detections</h1>
              <p className="text-sm text-zinc-500">{org.name} &middot; {total} total</p>
            </div>
          </div>
          {refreshedAt && (
            <span className="inline-flex items-center gap-1.5 text-xs text-zinc-500" title="Refreshes every 30 seconds while this tab is visible">
              <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
              Updated {refreshedAt.toLocaleTimeString()}
            </span>
          )}
        </div>

        {/* Filters */}
        <div className="flex gap-3 mb-6 flex-wrap">
          <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(0); }}
            className="rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-300 px-3 py-2 text-sm">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(0); }}
            className="rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-300 px-3 py-2 text-sm">
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        {highlightId && !inList && pinned && (
          <div className="mb-6">
            <p className="text-xs uppercase tracking-wide text-zinc-500 mb-2">Linked detection</p>
            {renderRow(pinned)}
          </div>
        )}

        {/* Detection List */}
        {detections.length === 0 ? (
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-12 text-center">
            {filtered ? (
              <p className="text-zinc-400 text-lg">No detections match these filters</p>
            ) : hasServers ? (
              <>
                <p className="text-zinc-400 text-lg mb-2">No detections yet</p>
                <p className="text-zinc-600 text-sm mb-6">
                  Linked servers report here as soon as their daemon detects something. A server that has never
                  been linked won&apos;t report; link it with:
                </p>
                <ConnectServerHint />
              </>
            ) : (
              <>
                <p className="text-zinc-400 text-lg mb-2">No servers connected</p>
                <p className="text-zinc-600 text-sm mb-6">Detections appear here once a server&apos;s daemon is linked to this organization.</p>
                <ConnectServerHint />
              </>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {detections.map(renderRow)}
          </div>
        )}

        {/* Pagination */}
        {total > limit && (
          <div className="flex items-center justify-between mt-6">
            <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
              className="rounded-lg px-4 py-2 text-sm bg-zinc-800 text-zinc-300 border border-zinc-700 hover:bg-zinc-700 disabled:opacity-40">
              Previous
            </button>
            <span className="text-zinc-500 text-sm">Page {page + 1} of {Math.ceil(total / limit)}</span>
            <button disabled={(page + 1) * limit >= total} onClick={() => setPage(p => p + 1)}
              className="rounded-lg px-4 py-2 text-sm bg-zinc-800 text-zinc-300 border border-zinc-700 hover:bg-zinc-700 disabled:opacity-40">
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
