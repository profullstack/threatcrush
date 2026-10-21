"use client";

import { useEffect, useState } from "react";

/** The line a buyer sees when CoinPay sends them back with ?payment=success|cancelled. */
export function PaymentNotice({ success }: { success: string }) {
  const [state, setState] = useState<string | null>(null);
  useEffect(() => {
    setState(new URLSearchParams(window.location.search).get("payment"));
  }, []);
  if (state !== "success" && state !== "cancelled") return null;
  return (
    <p
      role="status"
      className={`mb-6 rounded-lg border p-4 text-sm ${state === "success" ? "border-tc-green/50 bg-tc-green/10 text-tc-green" : "border-tc-border bg-tc-card text-tc-text-dim"}`}
    >
      {state === "success"
        ? success
        : "Checkout was cancelled and nothing was charged."}
    </p>
  );
}
