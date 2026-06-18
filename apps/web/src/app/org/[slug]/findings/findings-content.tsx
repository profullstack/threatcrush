"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, listServers, type Server } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
import Link from "next/link";

interface Finding {
  id: string;
  server_id: string;
  finding_key: string;
  severity: string;
  status: string;
  title: string;
  recommendation: string | null;
  observed_at: string;
}

interface ServerFindings {
  server: Server;
  findings: Finding[];
  score: number;
}

interface Organization { id: string; name: string; slug: string; }

const STATUS_ICONS: Record<string, { icon: string; color: string }> = {
  pass: { icon: "\u2713", color: "text-green-400" },
  warn: { icon: "!", color: "text-yellow-400" },
  fail: { icon: "\u2717", color: "text-red-400" },
  acknowledged: { icon: "\u2026", color: "text-yellow-400" },
  resolved: { icon: "\u2713", color: "text-blue-400" },
};

export default function FindingsContent({ slug }: { slug: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [serverFindings, setServerFindings] = useState<ServerFindings[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!signedIn || authLoading) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find(o => o.slug === slug);
        if (!found) return;
        setOrg(found);

        const { servers } = await listServers(found.id);
        const srvs = servers as unknown as Server[];

        const results: ServerFindings[] = [];
        for (const srv of srvs) {
          try {
            const res = await fetch(`/api/orgs/${found.id}/servers/${srv.id}/findings`, { headers: authHeaders() });
            if (res.ok) {
              const data = await res.json();
              results.push({ server: srv, findings: data.findings || [], score: data.score ?? 100 });
            }
          } catch { /* skip */ }
        }
        results.sort((a, b) => a.score - b.score);
        setServerFindings(results);
      } catch { /* ignore */ }
      finally { setLoading(false); }
    })();
  }, [signedIn, authLoading, slug]);

  const updateFinding = async (serverId: string, findingId: string, newStatus: string) => {
    if (!org) return;
    await fetch(`/api/orgs/${org.id}/servers/${serverId}/findings`, {
      method: "PATCH",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId, status: newStatus }),
    });
    // Refresh
    const res = await fetch(`/api/orgs/${org.id}/servers/${serverId}/findings`, { headers: authHeaders() });
    if (res.ok) {
      const data = await res.json();
      setServerFindings(prev => prev.map(sf =>
        sf.server.id === serverId ? { ...sf, findings: data.findings, score: data.score } : sf
      ));
    }
  };

  if (authLoading || loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  }

  if (!org) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Organization not found</div></div>;
  }

  const avgScore = serverFindings.length > 0
    ? Math.round(serverFindings.reduce((sum, sf) => sum + sf.score, 0) / serverFindings.length)
    : 100;

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Link href={`/org/${slug}`} className="text-zinc-500 hover:text-zinc-300">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">Hardening Findings</h1>
              <p className="text-sm text-zinc-500">{org.name}</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-sm text-zinc-500">Fleet Score</p>
            <p className={`text-3xl font-bold ${avgScore >= 80 ? "text-green-400" : avgScore >= 60 ? "text-yellow-400" : "text-red-400"}`}>
              {avgScore}/100
            </p>
          </div>
        </div>

        {serverFindings.length === 0 ? (
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-12 text-center">
            <p className="text-zinc-400 text-lg mb-2">No hardening data yet</p>
            <p className="text-zinc-600 text-sm">Run <code className="text-green-400">threatcrush harden</code> on enrolled servers to generate findings.</p>
          </div>
        ) : (
          <div className="space-y-6">
            {serverFindings.map(({ server, findings, score }) => (
              <div key={server.id} className="rounded-lg bg-zinc-900 border border-zinc-800 overflow-hidden">
                <div className="flex items-center justify-between p-4 border-b border-zinc-800">
                  <div className="flex items-center gap-3">
                    <span className={`h-2 w-2 rounded-full ${server.status === "online" ? "bg-green-400" : "bg-zinc-600"}`} />
                    <h3 className="text-white font-medium">{server.name}</h3>
                    <span className="text-zinc-500 text-sm">{server.hostname || server.ip_address}</span>
                  </div>
                  <span className={`text-lg font-bold ${score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                    {score}/100
                  </span>
                </div>
                <div className="divide-y divide-zinc-800">
                  {findings.map(f => {
                    const si = STATUS_ICONS[f.status] || STATUS_ICONS.fail;
                    return (
                      <div key={f.id} className="flex items-start justify-between p-4 hover:bg-zinc-800/50 transition-colors">
                        <div className="flex gap-3">
                          <span className={`text-lg ${si.color} mt-0.5`}>{si.icon}</span>
                          <div>
                            <p className="text-white font-medium">{f.title}</p>
                            {f.recommendation && <p className="text-zinc-400 text-sm mt-1">{f.recommendation}</p>}
                            <span className="text-xs text-zinc-600 mt-1">{f.finding_key}</span>
                          </div>
                        </div>
                        <div className="flex gap-2 shrink-0 ml-4">
                          {f.status === "fail" && (
                            <button onClick={() => updateFinding(server.id, f.id, "acknowledged")}
                              className="rounded px-2 py-1 text-xs bg-zinc-800 text-yellow-400 border border-zinc-700 hover:bg-zinc-700">
                              Acknowledge
                            </button>
                          )}
                          {f.status !== "resolved" && f.status !== "pass" && (
                            <button onClick={() => updateFinding(server.id, f.id, "resolved")}
                              className="rounded px-2 py-1 text-xs bg-zinc-800 text-green-400 border border-zinc-700 hover:bg-zinc-700">
                              Resolve
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
