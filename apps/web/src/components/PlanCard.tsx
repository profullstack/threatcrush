"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { authHeaders } from "@/lib/auth-client";

interface Billing {
  plan: "free" | "paid";
  orgs: Array<{ org_id: string; reputation: "free" | "pro"; modules: Record<string, { active: boolean; until: string | null }> }>;
  scans: Array<{ id: string; target: string | null; status: string }>;
}

/** What this account pays for, and the upgrade prompt when it is nothing yet. */
export function PlanCard() {
  const [b, setB] = useState<Billing | null>(null);
  useEffect(() => {
    fetch("/api/billing", { headers: authHeaders(), cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then(setB)
      .catch(() => setB(null));
  }, []);

  const pro = b?.orgs.some((o) => o.reputation === "pro");
  const linkWatch = b?.orgs.some((o) => o.modules["link-watch"]?.active);

  return (
    <div className="bg-tc-card border border-tc-green/40 rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-2">Plan</h2>
      {!b || b.plan === "free" ? (
        <>
          <p className="text-tc-text-dim text-sm mb-3">
            You are on Free: 100 reputation lookups a day, no watch lists, no Link Watch. Reputation Pro is $15/mo
            (10,000 lookups a day, history, ASN, watch lists); Link Watch is $9/mo; a human-reviewed scan is $400.
          </p>
          <Link
            href="/pricing"
            className="inline-block rounded-lg bg-tc-green px-4 py-2 text-sm font-bold text-black hover:opacity-90"
          >
            Upgrade
          </Link>
        </>
      ) : (
        <ul className="text-sm text-tc-text-dim space-y-1">
          <li>Reputation: {pro ? "Pro" : "Free"}</li>
          <li>Link Watch: {linkWatch ? "on" : "off"}</li>
          <li>
            <Link href="/pricing" className="text-tc-green hover:underline">
              Add more →
            </Link>
          </li>
        </ul>
      )}
      {b && b.scans.length > 0 && (
        <p className="mt-3 text-sm text-tc-text-dim">
          Scans booked: {b.scans.map((s) => s.target ?? "(target to confirm)").join(", ")}
        </p>
      )}
    </div>
  );
}
