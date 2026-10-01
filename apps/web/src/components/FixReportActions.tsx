"use client";

import { useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

interface Share {
  url: string;
  created_at: string;
  last_viewed_at: string | null;
}

/**
 * "Copy fix prompt" puts every open finding (plus a summary of recent
 * attacks) on the clipboard as a prompt for an AI agent. Owners and admins can
 * also publish the same report at a private link an agent can fetch itself.
 */
export default function FixReportActions({ orgId, canManage }: { orgId: string; canManage: boolean }) {
  const [copied, setCopied] = useState<"prompt" | "link" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [share, setShare] = useState<Share | null>(null);
  const [shareOpen, setShareOpen] = useState(false);

  useEffect(() => {
    if (!canManage) return;
    fetch(`/api/orgs/${orgId}/report-share`, { headers: authHeaders(), cache: "no-store" })
      .then((res) => (res.ok ? res.json() : { share: null }))
      .then((data: { share: Share | null }) => setShare(data.share))
      .catch(() => { /* the copy button still works */ });
  }, [orgId, canManage]);

  const flash = (what: "prompt" | "link") => {
    setCopied(what);
    setTimeout(() => setCopied(null), 2000);
  };

  const copyPrompt = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await fetch(`/api/orgs/${orgId}/report`, { headers: authHeaders(), cache: "no-store" });
      const data = (await res.json().catch(() => ({}))) as { prompt?: string; error?: string };
      if (!res.ok || !data.prompt) throw new Error(data.error || "Could not build the prompt");
      await navigator.clipboard.writeText(data.prompt);
      flash("prompt");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const changeShare = async (method: "POST" | "DELETE") => {
    setBusy(true);
    setError("");
    try {
      const res = await fetch(`/api/orgs/${orgId}/report-share`, { method, headers: authHeaders() });
      const data = (await res.json().catch(() => ({}))) as { share?: Share | null; error?: string };
      if (!res.ok) throw new Error(data.error || "Could not update the link");
      setShare(data.share ?? null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const button = "rounded-lg px-3 py-1.5 text-sm font-medium border transition-colors disabled:opacity-50";

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex flex-wrap items-center justify-end gap-2">
        <button
          type="button"
          onClick={copyPrompt}
          disabled={busy}
          className={`${button} text-black bg-green-500 border-green-500 hover:bg-green-400`}
          title="Copy every open finding as a prompt for an AI agent"
        >
          {copied === "prompt" ? "Copied" : "Copy fix prompt"}
        </button>
        {canManage && (
          <button
            type="button"
            onClick={() => setShareOpen((v) => !v)}
            className={`${button} text-zinc-300 bg-zinc-800 border-zinc-700 hover:bg-zinc-700`}
          >
            {share ? "Public report: on" : "Share public report"}
          </button>
        )}
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      {canManage && shareOpen && (
        <div className="w-full max-w-md rounded-lg bg-zinc-900 border border-zinc-800 p-4 text-sm">
          {share ? (
            <>
              <p className="text-zinc-300">Anyone with this link can read this organization&apos;s open findings and attack summary. Give it to an AI agent to work from.</p>
              <div className="mt-3 flex gap-2">
                <input
                  readOnly
                  value={share.url}
                  onFocus={(e) => e.currentTarget.select()}
                  className="flex-1 min-w-0 rounded bg-zinc-950 border border-zinc-700 px-2 py-1 text-xs text-zinc-200 font-mono"
                  aria-label="Public report link"
                />
                <button
                  type="button"
                  onClick={async () => { await navigator.clipboard.writeText(share.url); flash("link"); }}
                  className={`${button} text-zinc-200 bg-zinc-800 border-zinc-700 hover:bg-zinc-700`}
                >
                  {copied === "link" ? "Copied" : "Copy"}
                </button>
              </div>
              <p className="mt-2 text-xs text-zinc-500">
                Markdown by default, add <code>?format=json</code> for data. Not indexed by search engines.
                {share.last_viewed_at ? ` Last read ${new Date(share.last_viewed_at).toLocaleString()}.` : " Not read yet."}
              </p>
              <button
                type="button"
                onClick={() => changeShare("DELETE")}
                disabled={busy}
                className="mt-3 text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
              >
                Revoke link
              </button>
            </>
          ) : (
            <>
              <p className="text-zinc-300">Publish this organization&apos;s open findings and attack summary at a private link an AI agent can fetch.</p>
              <p className="mt-2 text-xs text-zinc-500">It includes server names and attacking IP addresses. You can revoke it at any time.</p>
              <button
                type="button"
                onClick={() => changeShare("POST")}
                disabled={busy}
                className={`mt-3 ${button} text-black bg-green-500 border-green-500 hover:bg-green-400`}
              >
                Create link
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
