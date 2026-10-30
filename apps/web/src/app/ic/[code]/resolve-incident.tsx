"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

export default function ResolveIncident({ code }: { code: string }) {
  const { signedIn, loading } = useAuth();
  const [message, setMessage] = useState("Opening incident…");

  useEffect(() => {
    if (loading) return;
    const path = `/ic/${encodeURIComponent(code)}`;
    if (!signedIn) {
      window.location.replace(`/auth/login?next=${encodeURIComponent(path)}`);
      return;
    }
    if (!/^[a-z0-9]{10,40}$/i.test(code)) {
      setMessage("Incident not found or you do not have permission to read it.");
      return;
    }

    let active = true;
    void fetch(`/api/incident-links/${encodeURIComponent(code)}`, { headers: authHeaders() })
      .then(async (res) => {
        const body = await res.json().catch(() => ({})) as { href?: unknown };
        if (!active) return;
        if (res.status === 401) {
          window.location.replace(`/auth/login?next=${encodeURIComponent(path)}`);
          return;
        }
        if (!res.ok || typeof body.href !== "string" || !body.href.startsWith("/org/")) {
          setMessage("Incident not found or you do not have permission to read it.");
          return;
        }
        window.location.replace(body.href);
      })
      .catch(() => {
        if (active) setMessage("Could not open this incident. Check your connection and try again.");
      });
    return () => { active = false; };
  }, [code, loading, signedIn]);

  return (
    <main className="min-h-screen bg-black flex items-center justify-center px-4">
      <p className="text-zinc-400">{message}</p>
    </main>
  );
}
