"use client";

import { useEffect } from "react";

// The real.clicks quote form (https://real.clicks.pit.world, Profullstack's verified-lead pilot).
// The widget shows the one partner firm a request goes to in its consent line and sends nothing
// until the reader confirms their email with a code. CSP: real.clicks.pit.world is allowed for
// script-src and style-src in next.config.ts; connect-src already allows https:.
const SRC = "https://real.clicks.pit.world/w.js";

declare global {
  interface Window {
    RealClicks?: { scan: () => void };
  }
}

export function QuoteForm({ title, blurb }: { title: string; blurb: string }) {
  useEffect(() => {
    if (window.RealClicks) {
      window.RealClicks.scan();
      return;
    }
    if (document.querySelector(`script[src="${SRC}"]`)) return;
    const s = document.createElement("script");
    s.src = SRC;
    s.defer = true;
    document.body.appendChild(s);
  }, []);
  return (
    <div className="rounded-2xl border border-tc-border bg-tc-card p-6">
      <h2 className="text-xl font-bold text-white">{title}</h2>
      <p className="mt-2 text-sm text-tc-text-dim">{blurb}</p>
      <div data-real-clicks="" data-niche="security" data-title="Get a pentest or assessment quote" />
    </div>
  );
}
