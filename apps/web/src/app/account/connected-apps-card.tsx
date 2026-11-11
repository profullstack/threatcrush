"use client";

import { useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

// Apps connected to this account over OAuth through the MCP server (ChatGPT,
// claude.ai, Claude Code, …). Disconnecting revokes the grant at once.

interface Grant {
  id: string;
  client_name: string;
  client_uri: string | null;
  created_at: string;
  last_used_at: string | null;
}

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "never");

export default function ConnectedAppsCard() {
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/oauth/grants", { headers: authHeaders(), cache: "no-store" })
      .then(async (r) => (r.ok ? setGrants(((await r.json()) as { grants: Grant[] }).grants) : setError("Could not load connected apps")))
      .catch(() => setError("Could not load connected apps"));
  }, []);

  const disconnect = async (id: string) => {
    const res = await fetch(`/api/oauth/grants?id=${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
    if (res.ok) setGrants((g) => g && g.filter((x) => x.id !== id));
    else setError("Could not disconnect");
  };

  return (
    <div className="bg-tc-card border border-tc-border rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-2">Connected apps</h2>
      <p className="text-tc-text-dim text-sm mb-4">
        AI apps you allowed to use ThreatCrush as you, through the MCP server at <code>https://threatcrush.com/api/mcp</code>{" "}
        (add it as a connector in ChatGPT or Claude).
      </p>
      {error && <p className="text-sm text-red-400 mb-2">{error}</p>}
      {grants && grants.length === 0 && <p className="text-sm text-tc-text-dim">No apps connected.</p>}
      {grants && grants.length > 0 && (
        <ul className="space-y-3">
          {grants.map((g) => (
            <li key={g.id} className="flex items-center justify-between gap-3">
              <div className="text-sm">
                <div className="text-white">{g.client_name}</div>
                <div className="text-xs text-tc-text-dim">
                  connected {when(g.created_at)} · last used {when(g.last_used_at)}
                </div>
              </div>
              <button
                type="button"
                onClick={() => disconnect(g.id)}
                className="text-xs border border-tc-border text-tc-text px-3 py-1 rounded-lg hover:border-red-500/50"
              >
                Disconnect
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
