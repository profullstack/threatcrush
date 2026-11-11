"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { authHeaders } from "@/lib/auth-client";
import { useAuth } from "@/lib/auth-context";
import { replaceLocation } from "@/lib/navigate";

// The OAuth authorization_endpoint for the MCP server. The session is in
// localStorage, so this page (not a server redirect) checks sign-in, shows
// consent, and posts the decision to /api/oauth/authorize with the Bearer
// session. Query params are read after mount: this page prerenders static.

interface Info {
  client: { name: string; uri: string | null };
  redirect_host: string;
}

/**
 * Back to the client. The server already matched this against the client's
 * registered redirect_uris; this only refuses anything that is not https or
 * http on loopback, the same rule registration applies.
 */
function returnToClient(url: string): boolean {
  try {
    const u = new URL(url);
    const loopback = u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    if (u.protocol !== "https:" && !loopback) return false;
    replaceLocation(u.toString());
    return true;
  } catch {
    return false;
  }
}

const PARAMS = ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "resource"];

export default function AuthorizeClient() {
  const { signedIn, loading: authLoading, profile } = useAuth();
  const [params, setParams] = useState<Record<string, string> | null>(null);
  const [info, setInfo] = useState<Info | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const p: Record<string, string> = {};
    for (const k of PARAMS) {
      const v = q.get(k);
      if (v !== null) p[k] = v;
    }
    setParams(p);
  }, []);

  // Validate the request before anything else: a bad client or redirect is shown here, never followed.
  useEffect(() => {
    if (!params) return;
    fetch(`/api/oauth/authorize?${new URLSearchParams(params)}`, { cache: "no-store" })
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as Partial<Info> & { redirect?: string; error_description?: string };
        if (data.redirect) {
          if (!returnToClient(data.redirect)) throw new Error("This connection request is not valid.");
          setLeaving(true);
          return;
        }
        if (!res.ok || !data.client) throw new Error(data.error_description || "This connection request is not valid.");
        setInfo(data as Info);
      })
      .catch((err: Error) => setError(err.message));
  }, [params]);

  // Not signed in: sign in (or sign up) first, then come straight back here.
  useEffect(() => {
    if (authLoading || signedIn || !info) return;
    const here = `${window.location.pathname}${window.location.search}`;
    window.location.href = `/auth/login?next=${encodeURIComponent(here)}`;
  }, [authLoading, signedIn, info]);

  const decide = async (approve: boolean) => {
    if (!params) return;
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/oauth/authorize", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ...params, approve }),
      });
      const data = (await res.json().catch(() => ({}))) as { redirect?: string; error?: string; error_description?: string };
      if (!res.ok || !data.redirect) throw new Error(data.error_description || data.error || "Could not complete the connection");
      if (!returnToClient(data.redirect)) throw new Error("This connection request is not valid.");
      setLeaving(true);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  const name = info?.client.name ?? "An app";

  return (
    <div className="min-h-screen bg-tc-darker flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="text-2xl font-bold text-tc-green glow-green font-mono">
            ⚡ ThreatCrush
          </Link>
          <h1 className="text-2xl font-bold text-white mt-4">Connect {info ? name : "an app"}</h1>
        </div>

        <div className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
          {error && (
            <div role="alert" className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">
              {error}
            </div>
          )}

          {leaving && <p className="text-tc-text-dim text-sm">Returning you to {info?.redirect_host ?? "the app"}…</p>}

          {!info && !error && !leaving && <p className="text-tc-text-dim text-sm">Checking the request…</p>}

          {info && signedIn && !leaving && (
            <>
              <p className="text-white">
                <strong>{name}</strong> wants to use your ThreatCrush account
                {profile?.email ? (
                  <>
                    {" "}(<span className="text-tc-green">{profile.email}</span>)
                  </>
                ) : null}
                .
              </p>
              <div className="text-sm text-tc-text-dim">
                <p className="mb-2">It will be able to, as you, in the organizations you belong to:</p>
                <ul className="list-disc pl-5 space-y-1">
                  <li>read your scan, pentest and ai-scan findings and triage them</li>
                  <li>read, update and raise incidents (raising one pages your team)</li>
                  <li>look up IP, domain and file-hash reputation</li>
                  <li>manage webhook endpoints, if you are an org admin</li>
                  <li>redeem credit codes and create invites</li>
                </ul>
              </div>
              <p className="text-xs text-tc-text-dim">
                You will be sent back to <span className="font-mono text-white">{info.redirect_host}</span>. Disconnect it
                any time under <Link href="/account" className="underline">Account → Connected apps</Link>. Only allow
                apps you just added yourself.
              </p>
              <div className="flex gap-3">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => decide(true)}
                  className="flex-1 bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Allow
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => decide(false)}
                  className="flex-1 border border-tc-border text-tc-text font-bold py-3 rounded-lg hover:border-red-500/50 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Deny
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
