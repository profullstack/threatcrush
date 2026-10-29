"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";
import { replaceLocation } from "@/lib/navigate";
import { FleetBar } from "./fleet-bar";

/** Where a signed-out visitor goes: the log in page, coming back here after. */
export const FLEET_SIGN_IN_URL = "/auth/login?next=%2Ffleet";

/** Re-mirror the session into the /api/fleetbar cookie this often, so it tracks the stored token. */
const SESSION_SYNC_MS = 10 * 60_000;

async function syncFleetSession(): Promise<boolean> {
  try {
    const res = await fetch("/api/fleet-session", { method: "POST", headers: authHeaders(), cache: "no-store" });
    return res.ok;
  } catch {
    return false;
  }
}

export default function FleetContent() {
  const { signedIn, loading, profile } = useAuth();
  const [ready, setReady] = useState(false);
  const [sessionError, setSessionError] = useState(false);

  useEffect(() => {
    if (loading) return;
    if (!signedIn) {
      replaceLocation(FLEET_SIGN_IN_URL);
      return;
    }
    let cancelled = false;
    void syncFleetSession().then((ok) => {
      if (cancelled) return;
      setReady(ok);
      setSessionError(!ok);
    });
    const timer = setInterval(() => void syncFleetSession(), SESSION_SYNC_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [loading, signedIn]);

  if (loading || !signedIn) {
    return <p className="text-sm text-tc-text-dim">Loading…</p>;
  }

  return (
    <>
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-white">Fleet</h1>
        <p className="mt-2 text-sm text-tc-text-dim">
          SSH, HTTP, keyword, SSL and TCP checks on your servers, run around the clock by{" "}
          <a href="https://crawlproof.com" className="text-tc-green hover:underline">crawlproof</a>, which calls or
          emails you when one goes down. The same checks appear on{" "}
          <a href="https://w3bs.org/fleet" className="text-tc-green hover:underline">w3bs.org/fleet</a>. Your
          ThreatCrush installs are on the{" "}
          <Link href="/dashboard" className="text-tc-green hover:underline">dashboard</Link>.
        </p>
        {profile && !profile.email_verified && (
          <p className="mt-2 text-sm text-yellow-400">
            Verify your email address on your <Link href="/account" className="underline">account</Link> to manage
            checks here.
          </p>
        )}
      </header>
      {sessionError && (
        <p className="text-sm text-red-400">Could not start a fleet session. Reload the page or sign in again.</p>
      )}
      {ready && (
        <div className="fleetbar-theme">
          <FleetBar />
        </div>
      )}
    </>
  );
}
