"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, listServers } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
import Link from "next/link";

interface Remediation {
  id: string;
  server_id: string;
  action_type: string;
  target_value: string;
  status: string;
  executed_at: string | null;
  expires_at: string | null;
  created_at: string;
}

interface AllowlistEntry {
  id: string;
  type: string;
  value: string;
  note: string | null;
  created_at: string;
}

interface Organization { id: string; name: string; slug: string; }

const ACTION_LABELS: Record<string, string> = {
  block: "Block",
  unblock: "Unblock",
  allowlist_add: "Allowlist Add",
  allowlist_remove: "Allowlist Remove",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "text-yellow-400",
  executed: "text-green-400",
  failed: "text-red-400",
  expired: "text-zinc-400",
  reversed: "text-blue-400",
};

export default function RemediationsContent({ slug }: { slug: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [servers, setServers] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"history" | "blocklist" | "allowlist">("history");
  const [blockIp, setBlockIp] = useState("");
  const [blockTtl, setBlockTtl] = useState("3600");
  const [blockServer, setBlockServer] = useState("");
  const [serverList, setServerList] = useState<Array<{ id: string; name: string }>>([]);
  const [allowIp, setAllowIp] = useState("");
  const [allowNote, setAllowNote] = useState("");

  const fetchData = useCallback(async (orgId: string) => {
    const [remRes, alRes] = await Promise.all([
      fetch(`/api/orgs/${orgId}/remediations`, { headers: authHeaders() }),
      fetch(`/api/orgs/${orgId}/allowlists`, { headers: authHeaders() }),
    ]);
    if (remRes.ok) { const d = await remRes.json(); setRemediations(d.remediations || []); }
    if (alRes.ok) { const d = await alRes.json(); setAllowlist(d.entries || []); }
  }, []);

  useEffect(() => {
    if (!signedIn || authLoading) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find(o => o.slug === slug);
        if (!found) return;
        setOrg(found);

        const { servers: srvs } = await listServers(found.id);
        const srvArr = srvs as unknown as Array<{ id: string; name: string }>;
        const map: Record<string, string> = {};
        srvArr.forEach(s => { map[s.id] = s.name; });
        setServers(map);
        setServerList(srvArr);
        if (srvArr.length > 0) setBlockServer(srvArr[0].id);

        await fetchData(found.id);
      } catch { /* ignore */ }
      finally { setLoading(false); }
    })();
  }, [signedIn, authLoading, slug, fetchData]);

  const handleBlock = async () => {
    if (!org || !blockIp || !blockServer) return;
    await fetch(`/api/orgs/${org.id}/remediations`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: blockServer, action_type: "block", target_value: blockIp, ttl_seconds: parseInt(blockTtl) || 3600 }),
    });
    setBlockIp("");
    await fetchData(org.id);
  };

  const handleUnblock = async (serverId: string, ip: string) => {
    if (!org) return;
    await fetch(`/api/orgs/${org.id}/remediations`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: serverId, action_type: "unblock", target_value: ip }),
    });
    await fetchData(org.id);
  };

  const handleAddAllowlist = async () => {
    if (!org || !allowIp) return;
    await fetch(`/api/orgs/${org.id}/allowlists`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ type: "ip", value: allowIp, note: allowNote || undefined }),
    });
    setAllowIp(""); setAllowNote("");
    await fetchData(org.id);
  };

  const handleRemoveAllowlist = async (entryId: string) => {
    if (!org) return;
    await fetch(`/api/orgs/${org.id}/allowlists?entry_id=${entryId}`, {
      method: "DELETE", headers: authHeaders(),
    });
    await fetchData(org.id);
  };

  if (authLoading || loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  }
  if (!org) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Organization not found</div></div>;
  }

  const activeBlocks = remediations.filter(r => r.action_type === "block" && (r.status === "pending" || r.status === "executed"));

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex items-center gap-3 mb-6">
          <Link href={`/org/${slug}`} className="text-zinc-500 hover:text-zinc-300">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Remediation & Blocklist</h1>
            <p className="text-sm text-zinc-500">{org.name}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-zinc-900 rounded-lg p-1 w-fit border border-zinc-800">
          {(["history", "blocklist", "allowlist"] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${tab === t ? "bg-zinc-700 text-white" : "text-zinc-400 hover:text-zinc-300"}`}>
              {t === "history" ? "History" : t === "blocklist" ? `Blocklist (${activeBlocks.length})` : `Allowlist (${allowlist.length})`}
            </button>
          ))}
        </div>

        {/* History Tab */}
        {tab === "history" && (
          <div className="space-y-3">
            {remediations.length === 0 ? (
              <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-12 text-center">
                <p className="text-zinc-400">No remediation actions yet</p>
              </div>
            ) : remediations.map(r => (
              <div key={r.id} className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-white font-medium">{ACTION_LABELS[r.action_type] || r.action_type}</span>
                    <code className="text-zinc-300 ml-2">{r.target_value}</code>
                    <span className="text-zinc-600 ml-2">on {servers[r.server_id] || r.server_id.slice(0, 8)}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`text-sm ${STATUS_COLORS[r.status] || "text-zinc-400"}`}>{r.status}</span>
                    {r.expires_at && (
                      <span className="text-xs text-zinc-500">
                        expires {new Date(r.expires_at).toLocaleString()}
                      </span>
                    )}
                    <span className="text-xs text-zinc-600">{new Date(r.created_at).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Blocklist Tab */}
        {tab === "blocklist" && (
          <div>
            <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 mb-4">
              <h3 className="text-white font-medium mb-3">Manual Block</h3>
              <div className="flex gap-3 flex-wrap">
                <input value={blockIp} onChange={e => setBlockIp(e.target.value)} placeholder="IP address"
                  className="rounded-lg bg-zinc-800 border border-zinc-700 text-white px-3 py-2 text-sm flex-1 min-w-[150px]" />
                <select value={blockServer} onChange={e => setBlockServer(e.target.value)}
                  className="rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-300 px-3 py-2 text-sm">
                  {serverList.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
                <select value={blockTtl} onChange={e => setBlockTtl(e.target.value)}
                  className="rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-300 px-3 py-2 text-sm">
                  <option value="1800">30 min</option>
                  <option value="3600">1 hour</option>
                  <option value="86400">24 hours</option>
                  <option value="604800">7 days</option>
                </select>
                <button onClick={handleBlock} disabled={!blockIp}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-500 disabled:opacity-40">
                  Block
                </button>
              </div>
            </div>
            <div className="space-y-2">
              {activeBlocks.length === 0 ? (
                <p className="text-zinc-500 text-center py-8">No active blocks</p>
              ) : activeBlocks.map(r => (
                <div key={r.id} className="flex items-center justify-between rounded-lg bg-zinc-900 border border-zinc-800 p-3">
                  <div>
                    <code className="text-red-400 font-medium">{r.target_value}</code>
                    <span className="text-zinc-600 ml-2">{servers[r.server_id] || ""}</span>
                    {r.expires_at && (
                      <span className="text-xs text-zinc-500 ml-2">
                        expires {new Date(r.expires_at).toLocaleString()}
                      </span>
                    )}
                  </div>
                  <button onClick={() => handleUnblock(r.server_id, r.target_value)}
                    className="rounded px-3 py-1 text-xs bg-zinc-800 text-green-400 border border-zinc-700 hover:bg-zinc-700">
                    Unblock
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Allowlist Tab */}
        {tab === "allowlist" && (
          <div>
            <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 mb-4">
              <h3 className="text-white font-medium mb-3">Add to Allowlist</h3>
              <div className="flex gap-3 flex-wrap">
                <input value={allowIp} onChange={e => setAllowIp(e.target.value)} placeholder="IP or CIDR"
                  className="rounded-lg bg-zinc-800 border border-zinc-700 text-white px-3 py-2 text-sm flex-1 min-w-[150px]" />
                <input value={allowNote} onChange={e => setAllowNote(e.target.value)} placeholder="Note (optional)"
                  className="rounded-lg bg-zinc-800 border border-zinc-700 text-white px-3 py-2 text-sm flex-1 min-w-[150px]" />
                <button onClick={handleAddAllowlist} disabled={!allowIp}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-40">
                  Add
                </button>
              </div>
            </div>
            <div className="space-y-2">
              {allowlist.length === 0 ? (
                <p className="text-zinc-500 text-center py-8">No allowlist entries</p>
              ) : allowlist.map(e => (
                <div key={e.id} className="flex items-center justify-between rounded-lg bg-zinc-900 border border-zinc-800 p-3">
                  <div>
                    <code className="text-green-400 font-medium">{e.value}</code>
                    <span className="text-zinc-600 text-sm ml-2">{e.type}</span>
                    {e.note && <span className="text-zinc-500 text-sm ml-2">&mdash; {e.note}</span>}
                  </div>
                  <button onClick={() => handleRemoveAllowlist(e.id)}
                    className="rounded px-3 py-1 text-xs bg-zinc-800 text-red-400 border border-zinc-700 hover:bg-zinc-700">
                    Remove
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
