"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

type Integration = {
  id: string;
  name: string;
  access_token: string;
  created_at: string;
  last_used_at: string | null;
  request_count: number;
};

export default function AdminContent() {
  const { signedIn, profile, loading } = useAuth();
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loadingList, setLoadingList] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("Outrank");
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [copied, setCopied] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const webhookUrl =
    typeof window !== "undefined"
      ? `${window.location.origin}/api/webhooks/outrank`
      : "/api/webhooks/outrank";

  const fetchIntegrations = useCallback(async () => {
    setLoadingList(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/integrations", {
        headers: authHeaders(),
      });
      if (!res.ok) {
        setError(res.status === 403 ? "Forbidden" : "Failed to load integrations");
        return;
      }
      const data = await res.json();
      setIntegrations(data.integrations || []);
    } catch {
      setError("Network error");
    } finally {
      setLoadingList(false);
    }
  }, []);

  useEffect(() => {
    if (signedIn && profile?.is_admin) {
      void fetchIntegrations();
    }
  }, [signedIn, profile?.is_admin, fetchIntegrations]);

  const handleCreate = async () => {
    setCreating(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/integrations", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ name: newName }),
      });
      if (!res.ok) {
        setError("Failed to create integration");
        return;
      }
      const data = await res.json();
      setIntegrations((prev) => [data.integration, ...prev]);
      setRevealed((prev) => ({ ...prev, [data.integration.id]: true }));
      setNewName("Outrank");
    } catch {
      setError("Network error");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this integration? Outrank will stop being able to publish.")) return;
    try {
      const res = await fetch(`/api/admin/integrations/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) {
        setError("Failed to delete");
        return;
      }
      setIntegrations((prev) => prev.filter((i) => i.id !== id));
    } catch {
      setError("Network error");
    }
  };

  const copy = (key: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-tc-darker flex items-center justify-center">
        <div className="text-tc-text-dim">Loading...</div>
      </div>
    );
  }

  if (!signedIn) {
    return (
      <div className="min-h-screen bg-tc-darker flex items-center justify-center">
        <div className="text-center">
          <p className="text-tc-text-dim mb-4">You need to log in.</p>
          <Link href="/auth/login" className="text-tc-green hover:underline">Log in →</Link>
        </div>
      </div>
    );
  }

  if (!profile?.is_admin) {
    return (
      <div className="min-h-screen bg-tc-darker flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-400 mb-2">403 — Forbidden</p>
          <p className="text-tc-text-dim mb-4">This area is restricted to administrators.</p>
          <Link href="/dashboard" className="text-tc-green hover:underline">Back to dashboard →</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-tc-darker">
      <nav className="border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <Link href="/" className="text-xl font-bold text-tc-green glow-green font-mono">
            ⚡ ThreatCrush
          </Link>
          <div className="flex items-center gap-4 text-sm">
            <Link href="/dashboard" className="text-tc-text-dim hover:text-tc-green transition-colors">Dashboard</Link>
            <Link href="/account" className="text-tc-text-dim hover:text-tc-green transition-colors">Account</Link>
          </div>
        </div>
      </nav>

      <div className="mx-auto max-w-4xl px-6 py-10">
        <h1 className="text-3xl font-bold text-white mb-2">Admin</h1>
        <p className="text-tc-text-dim mb-8">Blog publishing webhooks (Outrank)</p>

        {error && (
          <div className="mb-4 rounded border border-red-500/50 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <section className="mb-8 rounded-lg border border-tc-border/50 bg-tc-dark p-6">
          <h2 className="text-lg font-semibold text-white mb-2">Webhook endpoint</h2>
          <p className="text-sm text-tc-text-dim mb-3">
            Paste this into the Outrank dashboard <em>Webhook URL</em> field.
          </p>
          <div className="flex gap-2">
            <code className="flex-1 break-all rounded bg-tc-darker px-3 py-2 text-sm text-tc-green font-mono">
              {webhookUrl}
            </code>
            <button
              onClick={() => copy("url", webhookUrl)}
              className="rounded bg-tc-green/10 px-3 py-2 text-sm text-tc-green hover:bg-tc-green/20"
            >
              {copied === "url" ? "Copied" : "Copy"}
            </button>
          </div>
        </section>

        <section className="rounded-lg border border-tc-border/50 bg-tc-dark p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Access tokens</h2>
            <button
              onClick={fetchIntegrations}
              disabled={loadingList}
              className="text-sm text-tc-text-dim hover:text-tc-green disabled:opacity-50"
            >
              {loadingList ? "Loading..." : "Refresh"}
            </button>
          </div>

          <div className="mb-6 flex gap-2">
            <input
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Integration name"
              className="flex-1 rounded bg-tc-darker px-3 py-2 text-sm text-white border border-tc-border/50 focus:border-tc-green focus:outline-none"
            />
            <button
              onClick={handleCreate}
              disabled={creating || !newName.trim()}
              className="rounded bg-tc-green px-4 py-2 text-sm font-medium text-tc-darker hover:bg-tc-green/90 disabled:opacity-50"
            >
              {creating ? "Creating..." : "Generate token"}
            </button>
          </div>

          {integrations.length === 0 ? (
            <p className="text-sm text-tc-text-dim">No integrations yet — generate a token above.</p>
          ) : (
            <ul className="space-y-3">
              {integrations.map((it) => {
                const isRevealed = !!revealed[it.id];
                const masked = `${it.access_token.slice(0, 8)}…${it.access_token.slice(-4)}`;
                return (
                  <li key={it.id} className="rounded border border-tc-border/40 bg-tc-darker p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline gap-3">
                          <span className="font-medium text-white">{it.name}</span>
                          <span className="text-xs text-tc-text-dim">
                            {it.request_count} requests
                            {it.last_used_at && ` · last ${new Date(it.last_used_at).toLocaleString()}`}
                          </span>
                        </div>
                        <div className="mt-2 flex items-center gap-2">
                          <code className="flex-1 break-all rounded bg-black/40 px-2 py-1 text-xs text-tc-green font-mono">
                            {isRevealed ? it.access_token : masked}
                          </code>
                          <button
                            onClick={() =>
                              setRevealed((prev) => ({ ...prev, [it.id]: !prev[it.id] }))
                            }
                            className="text-xs text-tc-text-dim hover:text-tc-green"
                          >
                            {isRevealed ? "Hide" : "Reveal"}
                          </button>
                          <button
                            onClick={() => copy(it.id, it.access_token)}
                            className="text-xs text-tc-text-dim hover:text-tc-green"
                          >
                            {copied === it.id ? "Copied" : "Copy"}
                          </button>
                        </div>
                        <p className="mt-2 text-xs text-tc-text-dim">
                          Use as <code className="text-tc-green">Authorization: Bearer &lt;token&gt;</code> in Outrank.
                          Created {new Date(it.created_at).toLocaleDateString()}.
                        </p>
                      </div>
                      <button
                        onClick={() => handleDelete(it.id)}
                        className="text-xs text-red-400 hover:text-red-300"
                      >
                        Revoke
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
