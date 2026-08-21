"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

const WEBHOOK_PATH = "/api/webhooks/github/marketplace";

const DOCS_HREF =
  "https://docs.github.com/en/apps/github-marketplace/listing-an-app-on-github-marketplace/configuring-a-webhook-to-notify-you-of-plan-changes";

type Subscription = {
  id: string;
  github_account_id: number;
  github_account_login: string;
  github_account_type: string | null;
  plan_name: string | null;
  plan_monthly_price_cents: number | null;
  billing_cycle: string | null;
  unit_count: number | null;
  on_free_trial: boolean;
  free_trial_ends_on: string | null;
  next_billing_date: string | null;
  status: string;
  pending_plan_name: string | null;
  pending_effective_date: string | null;
  last_action: string | null;
  updated_at: string;
};

type Delivery = {
  id: string;
  delivery_id: string | null;
  action: string;
  github_account_login: string | null;
  applied: boolean;
  skip_reason: string | null;
  received_at: string;
};

type MarketplaceData = {
  configured: boolean;
  migrationApplied: boolean;
  subscriptions: Subscription[];
  events: Delivery[];
};

function fmtDate(value: string | null): string {
  if (!value) return "—";
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return "—";
  return new Date(ms).toISOString().slice(0, 10);
}

function fmtPrice(cents: number | null): string {
  if (typeof cents !== "number") return "—";
  return cents === 0 ? "Free" : `$${(cents / 100).toFixed(2)}`;
}

export default function MarketplacePanel() {
  const [data, setData] = useState<MarketplaceData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const webhookUrl =
    typeof window === "undefined" ? WEBHOOK_PATH : `${window.location.origin}${WEBHOOK_PATH}`;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/marketplace", { headers: authHeaders() });
      if (!res.ok) {
        setError(res.status === 403 ? "Forbidden" : "Failed to load Marketplace data");
        return;
      }
      setData((await res.json()) as MarketplaceData);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const copy = () => {
    navigator.clipboard?.writeText(webhookUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const subs = data?.subscriptions ?? [];
  const events = data?.events ?? [];
  const active = subs.filter((s) => s.status === "active").length;

  return (
    <section className="mt-8 rounded-lg border border-tc-border/50 bg-tc-dark p-6">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">
          GitHub Marketplace
          <a
            href={DOCS_HREF}
            target="_blank"
            rel="noreferrer"
            className="ml-2 text-xs font-normal text-tc-text-dim hover:text-tc-green"
          >
            docs ↗
          </a>
        </h2>
        <button
          onClick={load}
          disabled={loading}
          className="text-sm text-tc-text-dim hover:text-tc-green disabled:opacity-50"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded border border-red-500/50 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <p className="mb-3 text-sm text-tc-text-dim">
        Paste this as the Payload URL on the listing&apos;s Webhook page. Content type{" "}
        <code className="text-tc-green">application/json</code>, and set a Secret.
      </p>

      <div className="mb-4 flex gap-2">
        <code className="flex-1 break-all rounded bg-tc-darker px-3 py-2 font-mono text-sm text-tc-green">
          {webhookUrl}
        </code>
        <button
          onClick={copy}
          className="rounded bg-tc-green/10 px-3 py-2 text-sm text-tc-green hover:bg-tc-green/20"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>

      <div className="mb-6 space-y-2 text-sm">
        <div className="flex items-center gap-2">
          <span className={data?.configured ? "text-tc-green" : "text-red-400"}>
            {data?.configured ? "●" : "○"}
          </span>
          <span className="text-tc-text-dim">
            {data?.configured
              ? "Secret configured (GITHUB_MARKETPLACE_WEBHOOK_SECRET)"
              : "No secret set. Deliveries are rejected with 503 until GITHUB_MARKETPLACE_WEBHOOK_SECRET is set on the service."}
          </span>
        </div>
        {data && !data.migrationApplied && (
          <div className="flex items-center gap-2">
            <span className="text-red-400">○</span>
            <span className="text-tc-text-dim">
              Tables missing. Apply{" "}
              <code className="text-tc-green">
                supabase/migrations/20260821170000_github_marketplace.sql
              </code>
              .
            </span>
          </div>
        )}
      </div>

      <h3 className="mb-2 text-sm font-medium text-white">
        Subscriptions{" "}
        <span className="font-normal text-tc-text-dim">
          ({active} active of {subs.length})
        </span>
      </h3>

      {subs.length === 0 ? (
        <p className="mb-6 text-sm text-tc-text-dim">
          No purchases recorded yet. GitHub does not resend failed deliveries, so if a customer
          reports a purchase that is missing here, replay it from the listing&apos;s delivery log.
        </p>
      ) : (
        <div className="mb-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-tc-text-dim">
              <tr className="border-b border-tc-border/50">
                <th className="py-2 pr-4 font-medium">Account</th>
                <th className="py-2 pr-4 font-medium">Plan</th>
                <th className="py-2 pr-4 font-medium">Cycle</th>
                <th className="py-2 pr-4 font-medium">Units</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Next billing</th>
              </tr>
            </thead>
            <tbody>
              {subs.map((s) => (
                <tr key={s.id} className="border-b border-tc-border/20">
                  <td className="py-2 pr-4">
                    <a
                      href={`https://github.com/${s.github_account_login}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-tc-green hover:underline"
                    >
                      {s.github_account_login}
                    </a>
                    <span className="ml-1 text-xs text-tc-text-dim">
                      {s.github_account_type === "Organization" ? "org" : "user"}
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-white">
                    {s.plan_name ?? "—"}
                    <span className="ml-1 text-xs text-tc-text-dim">
                      {fmtPrice(s.plan_monthly_price_cents)}
                    </span>
                    {s.pending_plan_name && (
                      <div className="text-xs text-yellow-400">
                        → {s.pending_plan_name} on {fmtDate(s.pending_effective_date)}
                      </div>
                    )}
                  </td>
                  <td className="py-2 pr-4 text-tc-text-dim">{s.billing_cycle ?? "—"}</td>
                  <td className="py-2 pr-4 text-tc-text-dim">{s.unit_count ?? "—"}</td>
                  <td className="py-2 pr-4">
                    <span
                      className={
                        s.status === "active" ? "text-tc-green" : "text-tc-text-dim line-through"
                      }
                    >
                      {s.status}
                    </span>
                    {s.on_free_trial && (
                      <span className="ml-1 text-xs text-yellow-400">
                        trial → {fmtDate(s.free_trial_ends_on)}
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-4 text-tc-text-dim">{fmtDate(s.next_billing_date)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 className="mb-2 text-sm font-medium text-white">Recent deliveries</h3>
      {events.length === 0 ? (
        <p className="text-sm text-tc-text-dim">Nothing delivered yet.</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {events.map((e) => (
            <li key={e.id} className="flex flex-wrap items-baseline gap-2">
              <span className={e.applied ? "text-tc-green" : "text-tc-text-dim"}>
                {e.applied ? "✓" : "·"}
              </span>
              <span className="font-mono text-white">{e.action}</span>
              <span className="text-tc-text-dim">{e.github_account_login ?? "unknown"}</span>
              <span className="text-xs text-tc-text-dim">
                {new Date(e.received_at).toISOString().replace("T", " ").slice(0, 16)}
              </span>
              {e.skip_reason && (
                <span className="text-xs text-yellow-400">skipped: {e.skip_reason}</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
