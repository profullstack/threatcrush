"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

type Status = { enabled: boolean; linked: boolean; email: string | null; name: string | null; canDisconnect: boolean };

const OUTCOMES: Record<string, string> = {
  linked: "CoinPay is connected. You can now sign in with CoinPay.",
  already_linked: "CoinPay was already connected to this account.",
  sub_taken: "That CoinPay account is already connected to a different ThreatCrush account.",
  user_has_other: "A different CoinPay account is already connected here. Disconnect it first.",
  denied: "CoinPay sign-in was cancelled.",
  failed: "CoinPay sign-in failed. Try again.",
};

/** "Connect CoinPay" / "Disconnect" on /account. */
export default function CoinpayCard() {
  const [status, setStatus] = useState<Status | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const res = await fetch("/api/v1/coinpay/link", { headers: authHeaders() });
    if (res.ok) setStatus(await res.json());
  }, []);

  useEffect(() => {
    const outcome = new URLSearchParams(window.location.search).get("coinpay");
    if (outcome && OUTCOMES[outcome]) setMessage(OUTCOMES[outcome]);
    void load();
  }, [load]);

  const connect = async () => {
    setBusy(true);
    setMessage("");
    try {
      const res = await fetch("/api/v1/coinpay/link", { method: "POST", headers: authHeaders(), credentials: "same-origin" });
      const data = await res.json();
      if (!res.ok || !data.url) {
        setMessage(data.error || "Could not start CoinPay");
        return;
      }
      window.location.href = data.url;
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async () => {
    setBusy(true);
    setMessage("");
    try {
      const res = await fetch("/api/v1/coinpay/link", { method: "DELETE", headers: authHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) setMessage(data.error || "Could not disconnect CoinPay");
      else setMessage("CoinPay is disconnected.");
      await load();
    } finally {
      setBusy(false);
    }
  };

  if (!status?.enabled) return null;

  return (
    <div className="bg-tc-card border border-tc-border rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-2">CoinPay</h2>
      <p className="text-sm text-tc-text-dim mb-4">
        {status.linked
          ? `Connected${status.name ? ` as ${status.name}` : ""}${status.email ? ` (${status.email})` : ""}. You can sign in with CoinPay.`
          : "Connect your CoinPay account to sign in to ThreatCrush with CoinPay."}
      </p>
      {message && <p role="status" className="text-sm text-tc-text mb-3">{message}</p>}
      {status.linked ? (
        status.canDisconnect ? (
          <button
            type="button"
            onClick={disconnect}
            disabled={busy}
            className="text-sm border border-tc-border text-white px-4 py-2 rounded-lg hover:border-red-400/50 disabled:opacity-50"
          >
            Disconnect CoinPay
          </button>
        ) : (
          <p className="text-xs text-tc-text-dim">CoinPay is how you sign in to this account, so it stays connected.</p>
        )
      ) : (
        <button
          type="button"
          onClick={connect}
          disabled={busy}
          className="text-sm bg-tc-green text-black font-semibold px-4 py-2 rounded-lg hover:bg-tc-green-dim disabled:opacity-50"
        >
          Connect CoinPay
        </button>
      )}
    </div>
  );
}
