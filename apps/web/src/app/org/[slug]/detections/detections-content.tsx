"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
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
  status: string;
}

interface Organization {
  id: string;
  name: string;
  slug: string;
}

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

export default function DetectionsContent({ slug }: { slug: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
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
    }
  }, [severity, status, page]);

  useEffect(() => {
    if (!signedIn || authLoading) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find(o => o.slug === slug);
        if (!found) return;
        setOrg(found);
        await fetchDetections(found.id);
      } catch { /* ignore */ }
      finally { setLoading(false); }
    })();
  }, [signedIn, authLoading, slug, fetchDetections]);

  const updateStatus = async (ids: string[], newStatus: string) => {
    if (!org) return;
    await fetch(`/api/orgs/${org.id}/detections`, {
      method: "PATCH",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ ids, status: newStatus }),
    });
    await fetchDetections(org.id);
  };

  if (authLoading || loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  }

  if (!org) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Organization not found</div></div>;
  }

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

        {/* Detection List */}
        {detections.length === 0 ? (
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-12 text-center">
            <p className="text-zinc-400 text-lg mb-2">No detections found</p>
            <p className="text-zinc-600 text-sm">Detections will appear here when the daemon reports security events.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {detections.map(d => (
              <div key={d.id} className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 hover:border-zinc-700 transition-colors">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${SEVERITY_COLORS[d.severity] || SEVERITY_COLORS.info}`}>
                        {d.severity.toUpperCase()}
                      </span>
                      <span className={`text-xs ${STATUS_COLORS[d.status] || "text-zinc-400"}`}>
                        {d.status}
                      </span>
                      {d.rule_id && <span className="text-xs text-zinc-600 font-mono">{d.rule_id}</span>}
                    </div>
                    <h3 className="text-white font-medium truncate">{d.title}</h3>
                    {d.description && <p className="text-zinc-400 text-sm mt-1 line-clamp-2">{d.description}</p>}
                    <div className="flex items-center gap-4 mt-2 text-xs text-zinc-500">
                      {d.source_ip && <span>IP: <code className="text-zinc-400">{d.source_ip}</code></span>}
                      {d.username && <span>User: <code className="text-zinc-400">{d.username}</code></span>}
                      <span>{new Date(d.detected_at).toLocaleString()}</span>
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
            ))}
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
