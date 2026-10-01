"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { authHeaders } from "@/lib/auth-client";
import { useAuth } from "@/lib/auth-context";

interface LoginRequest {
  id: string;
  user_code: string;
  device_name: string | null;
  status: "pending" | "approved" | "denied" | "consumed" | "expired";
  created_at: string;
}

type Outcome = "approved" | "denied" | null;

export default function CliLoginClient() {
  const { signedIn, loading: authLoading, profile } = useAuth();
  const [requestId, setRequestId] = useState<string | null>(null);
  const [request, setRequest] = useState<LoginRequest | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>(null);

  useEffect(() => {
    setRequestId(new URLSearchParams(window.location.search).get("request"));
  }, []);

  // Not signed in: sign in first, then come straight back to this request.
  useEffect(() => {
    if (authLoading || signedIn) return;
    const here = `${window.location.pathname}${window.location.search}`;
    window.location.href = `/auth/login?next=${encodeURIComponent(here)}`;
  }, [authLoading, signedIn]);

  useEffect(() => {
    if (!signedIn || !requestId) return;
    fetch(`/api/auth/cli/request?id=${encodeURIComponent(requestId)}`, {
      headers: authHeaders(),
      cache: "no-store",
    })
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as { request?: LoginRequest; error?: string };
        if (!res.ok || !data.request) throw new Error(data.error || "Unknown login request");
        setRequest(data.request);
      })
      .catch((err: Error) => setError(err.message));
  }, [signedIn, requestId]);

  const decide = async (approve: boolean) => {
    if (!request) return;
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/auth/cli/approve", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ request_id: request.id, approve }),
      });
      const data = (await res.json().catch(() => ({}))) as { status?: string; error?: string };
      if (!res.ok) throw new Error(data.error || "Could not update the login request");
      setOutcome(approve ? "approved" : "denied");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const closed = request && request.status !== "pending";

  return (
    <div className="min-h-screen bg-tc-darker flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="text-2xl font-bold text-tc-green glow-green font-mono">
            ⚡ ThreatCrush
          </Link>
          <h1 className="text-2xl font-bold text-white mt-4">Approve CLI login</h1>
          <p className="text-tc-text-dim mt-2">
            A terminal is asking to sign in to your account.
          </p>
        </div>

        <div className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
          {error && (
            <div role="alert" className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">
              {error}
            </div>
          )}

          {!requestId && !error && (
            <p className="text-tc-text-dim text-sm">
              This link is missing its request. Run <code className="text-tc-green">threatcrush login</code> again
              and open the link it prints.
            </p>
          )}

          {outcome === "approved" && (
            <div role="status" className="bg-tc-green/10 border border-tc-green/30 text-tc-green rounded-lg px-4 py-3 text-sm">
              Approved. The terminal will finish signing in within a few seconds. You can close this tab.
            </div>
          )}
          {outcome === "denied" && (
            <div role="status" className="bg-tc-card border border-tc-border text-tc-text rounded-lg px-4 py-3 text-sm">
              Denied. The terminal was not signed in.
            </div>
          )}

          {request && !outcome && (
            <>
              <dl className="space-y-3 text-sm">
                <div>
                  <dt className="text-tc-text-dim">Machine</dt>
                  <dd className="text-white font-mono">{request.device_name || "unnamed"}</dd>
                </div>
                <div>
                  <dt className="text-tc-text-dim">Code shown in the terminal</dt>
                  <dd className="text-tc-green font-mono text-2xl tracking-widest">{request.user_code}</dd>
                </div>
                {profile?.email && (
                  <div>
                    <dt className="text-tc-text-dim">Signs in as</dt>
                    <dd className="text-white">{profile.email}</dd>
                  </div>
                )}
              </dl>

              {closed ? (
                <p className="text-tc-text-dim text-sm">
                  This request is {request.status === "expired" ? "expired" : "already used"}. Run{" "}
                  <code className="text-tc-green">threatcrush login</code> again for a new link.
                </p>
              ) : (
                <>
                  <p className="text-tc-text-dim text-sm">
                    Only approve if you just ran <code className="text-tc-green">threatcrush login</code> and the
                    code matches what your terminal shows.
                  </p>
                  <div className="flex gap-3">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => decide(true)}
                      className="flex-1 bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Approve
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
            </>
          )}
        </div>
      </div>
    </div>
  );
}
