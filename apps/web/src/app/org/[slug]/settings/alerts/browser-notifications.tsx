"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";
import {
  getBrowserPushSubscription,
  isBrowserPushSupported,
  subscribeBrowserPush,
  unsubscribeBrowserPush,
} from "@/lib/pwa-client";

const VAPID_PUBLIC_KEY = process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY || "";

type State = "loading" | "unsupported" | "no-key" | "denied" | "on" | "off";

export default function BrowserNotifications({ orgId }: { orgId: string }) {
  const [state, setState] = useState<State>("loading");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    if (!isBrowserPushSupported()) return setState("unsupported");
    if (!VAPID_PUBLIC_KEY) return setState("no-key");
    if (Notification.permission === "denied") return setState("denied");

    const subscription = await getBrowserPushSubscription();
    if (!subscription) return setState("off");
    // A browser holds one subscription; it may be registered for another org.
    const res = await fetch(`/api/orgs/${orgId}/push-subscriptions`, { headers: authHeaders() });
    const data = res.ok ? await res.json() : { subscriptions: [] };
    const registered = (data.subscriptions as { endpoint: string }[]).some(
      (row) => row.endpoint === subscription.endpoint,
    );
    setState(registered ? "on" : "off");
  }, [orgId]);

  useEffect(() => {
    refresh().catch((err) => {
      setError((err as Error).message);
      setState("off");
    });
  }, [refresh]);

  const enable = async () => {
    setBusy(true);
    setError("");
    try {
      const subscription = await subscribeBrowserPush(VAPID_PUBLIC_KEY);
      const res = await fetch(`/api/orgs/${orgId}/push-subscriptions`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "webpush", subscription: subscription.toJSON() }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        await subscription.unsubscribe();
        throw new Error(data.error || "Could not register this browser");
      }
      setState("on");
    } catch (err) {
      if (Notification.permission === "denied") setState("denied");
      else setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    setBusy(true);
    setError("");
    try {
      const endpoint = await unsubscribeBrowserPush();
      if (endpoint) {
        await fetch(`/api/orgs/${orgId}/push-subscriptions`, {
          method: "DELETE",
          headers: { ...authHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify({ endpoint }),
        });
      }
      setState("off");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const message: Record<State, string> = {
    loading: "Checking this browser…",
    unsupported:
      "This browser can't receive push notifications. On iPhone and iPad, add ThreatCrush to your Home Screen first, then open it from there.",
    "no-key": "Browser notifications aren't configured on this server (no VAPID public key).",
    denied: "Notifications are blocked for this site. Allow them in your browser's site settings, then reload this page.",
    on: "This browser receives alerts from rules that route to a Push destination.",
    off: "Get alerts from rules that route to a Push destination as notifications in this browser.",
  };

  return (
    <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 mb-6 flex items-center justify-between gap-4">
      <div>
        <div className="text-white font-medium">Browser notifications</div>
        <p className="text-sm text-zinc-500 mt-1" data-testid="browser-push-status">{message[state]}</p>
        {error && <p className="text-sm text-red-400 mt-1">{error}</p>}
      </div>
      {state === "on" && (
        <button onClick={disable} disabled={busy}
          className="shrink-0 rounded-lg px-4 py-2 text-sm bg-zinc-800 text-red-400 border border-zinc-700 hover:bg-zinc-700 disabled:opacity-40">
          Turn off
        </button>
      )}
      {state === "off" && (
        <button onClick={enable} disabled={busy}
          className="shrink-0 rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-40">
          Enable
        </button>
      )}
    </div>
  );
}
