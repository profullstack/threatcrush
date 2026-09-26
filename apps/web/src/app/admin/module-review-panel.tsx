"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { authHeaders } from "@/lib/auth-client";
import { isSourceBroken, type ReviewStatus, type SourceStatus } from "@/lib/module-marketplace";

type AdminModule = {
  id: string;
  slug: string;
  display_name: string;
  description: string | null;
  author_name: string | null;
  author_email: string | null;
  git_url: string | null;
  homepage_url: string | null;
  npm_package: string | null;
  tarball_url: string | null;
  pricing_type: string | null;
  price_usd: number | null;
  downloads: number | null;
  published: boolean;
  review_status: ReviewStatus;
  reviewed_at: string | null;
  review_note: string | null;
  reviewer: { email: string } | null;
  source_status: SourceStatus | null;
  source_checked_at: string | null;
  source_check_detail: string | null;
  created_at: string;
};

type Filter = "pending" | "broken" | "approved" | "rejected" | "all";

const FILTERS: Array<{ key: Filter; label: string; match: (m: AdminModule) => boolean }> = [
  { key: "pending", label: "Pending", match: (m) => m.review_status === "pending" },
  { key: "broken", label: "Broken source", match: (m) => isSourceBroken(m.source_status) },
  { key: "approved", label: "Approved", match: (m) => m.review_status === "approved" },
  { key: "rejected", label: "Rejected", match: (m) => m.review_status === "rejected" },
  { key: "all", label: "All", match: () => true },
];

const REVIEW_COLOR: Record<ReviewStatus, string> = {
  pending: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
  approved: "border-tc-green/40 bg-tc-green/10 text-tc-green",
  rejected: "border-red-500/40 bg-red-500/10 text-red-300",
};

const SOURCE_LABEL: Record<SourceStatus, string> = {
  ok: "source ok",
  unreachable: "source unreachable",
  not_found: "source not found",
};

function fmtTime(value: string | null): string {
  if (!value) return "—";
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return "—";
  return new Date(ms).toISOString().slice(0, 16).replace("T", " ");
}

export default function ModuleReviewPanel() {
  const [modules, setModules] = useState<AdminModule[]>([]);
  const [filter, setFilter] = useState<Filter>("pending");
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/marketplace/modules", { headers: authHeaders() });
      if (!res.ok) {
        setError(res.status === 403 ? "Forbidden" : "Failed to load modules");
        return;
      }
      setModules(((await res.json()) as { modules: AdminModule[] }).modules);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const review = async (mod: AdminModule, action: "approve" | "reject" | "unpublish") => {
    setBusy(`${mod.slug}:${action}`);
    setError(null);
    try {
      const res = await fetch(`/api/admin/marketplace/modules/${encodeURIComponent(mod.slug)}`, {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ action, note: notes[mod.slug] ?? "" }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || `Failed to ${action} ${mod.slug}`);
        return;
      }
      setModules((prev) => prev.map((m) => (m.slug === mod.slug ? (data.module as AdminModule) : m)));
      setNotes((prev) => ({ ...prev, [mod.slug]: "" }));
    } catch {
      setError("Network error");
    } finally {
      setBusy(null);
    }
  };

  const checkSources = async (slug?: string) => {
    setBusy(slug ? `${slug}:check` : "check-all");
    setError(null);
    try {
      const res = await fetch("/api/admin/marketplace/source-health", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(slug ? { slug } : {}),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || "Source check failed");
        return;
      }
      await load();
    } catch {
      setError("Network error");
    } finally {
      setBusy(null);
    }
  };

  const active = FILTERS.find((f) => f.key === filter) ?? FILTERS[0];
  const shown = modules.filter(active.match);

  return (
    <section className="mt-8 rounded-lg border border-tc-border/50 bg-tc-dark p-6">
      <div className="mb-4 flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold text-white">Module store review</h2>
        <div className="flex items-center gap-4 text-sm">
          <button
            onClick={() => checkSources()}
            disabled={busy !== null}
            className="rounded bg-tc-green/10 px-3 py-1.5 text-tc-green hover:bg-tc-green/20 disabled:opacity-50"
          >
            {busy === "check-all" ? "Checking sources..." : "Check all sources"}
          </button>
          <button
            onClick={load}
            disabled={loading}
            className="text-tc-text-dim hover:text-tc-green disabled:opacity-50"
          >
            {loading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>

      <p className="mb-4 text-sm text-tc-text-dim">
        Submissions stay out of the store until approved. The source check resolves each listing&apos;s
        install source (npm package, git repository, tarball, or homepage when there is none); installs
        of a listing whose source is unreachable or not found are refused until it passes again.
      </p>

      {error && (
        <div className="mb-4 rounded border border-red-500/50 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="mb-4 flex flex-wrap gap-2 text-sm">
        {FILTERS.map((f) => {
          const count = modules.filter(f.match).length;
          return (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={`rounded border px-3 py-1 ${
                filter === f.key
                  ? "border-tc-green/60 bg-tc-green/10 text-tc-green"
                  : "border-tc-border/50 text-tc-text-dim hover:text-tc-green"
              }`}
            >
              {f.label} <span className={f.key === "broken" && count > 0 ? "text-red-400" : "text-white"}>{count}</span>
            </button>
          );
        })}
      </div>

      {shown.length === 0 ? (
        <p className="text-sm text-tc-text-dim">Nothing here.</p>
      ) : (
        <ul className="space-y-3">
          {shown.map((mod) => {
            const broken = isSourceBroken(mod.source_status);
            const source = mod.npm_package
              ? `npm: ${mod.npm_package}`
              : mod.git_url || mod.tarball_url || (mod.homepage_url ? `homepage: ${mod.homepage_url}` : "no source URL");
            return (
              <li
                key={mod.id}
                className={`rounded border p-4 ${broken ? "border-red-500/50 bg-red-500/5" : "border-tc-border/40 bg-tc-darker"}`}
              >
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-medium text-white">{mod.display_name}</span>
                  <Link href={`/store/${mod.slug}`} className="font-mono text-xs text-tc-text-dim hover:text-tc-green">
                    {mod.slug}
                  </Link>
                  <span className={`rounded border px-2 py-0.5 text-xs ${REVIEW_COLOR[mod.review_status]}`}>
                    {mod.review_status}
                  </span>
                  <span className="text-xs text-tc-text-dim">{mod.published ? "published" : "not published"}</span>
                  {mod.source_status && (
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${broken ? "bg-red-500/20 text-red-300" : "bg-tc-green/10 text-tc-green"}`}
                    >
                      {SOURCE_LABEL[mod.source_status]}
                    </span>
                  )}
                  {mod.pricing_type && mod.pricing_type !== "free" && (
                    <span className="rounded bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-300">
                      {mod.pricing_type}
                      {mod.price_usd ? ` $${mod.price_usd}` : ""}
                    </span>
                  )}
                </div>

                <div className="mt-2 space-y-1 text-xs text-tc-text-dim">
                  <p>
                    by {mod.author_name || "—"} &lt;{mod.author_email || "no email"}&gt; · submitted {fmtTime(mod.created_at)} ·{" "}
                    {mod.downloads ?? 0} downloads
                  </p>
                  <p className="break-all font-mono">{source}</p>
                  <p>
                    Source check: {mod.source_status ? `${mod.source_check_detail ?? mod.source_status} · ${fmtTime(mod.source_checked_at)}` : "never checked"}
                  </p>
                  {mod.reviewed_at && (
                    <p>
                      Reviewed {fmtTime(mod.reviewed_at)} by {mod.reviewer?.email ?? "system"}
                      {mod.review_note ? ` — ${mod.review_note}` : ""}
                    </p>
                  )}
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={notes[mod.slug] ?? ""}
                    onChange={(e) => setNotes((prev) => ({ ...prev, [mod.slug]: e.target.value }))}
                    placeholder="Note (required to reject)"
                    className="min-w-0 flex-1 rounded border border-tc-border/50 bg-tc-dark px-2 py-1 text-xs text-white focus:border-tc-green focus:outline-none"
                  />
                  {(mod.review_status !== "approved" || !mod.published) && (
                    <button
                      onClick={() => review(mod, "approve")}
                      disabled={busy !== null}
                      className="rounded bg-tc-green px-3 py-1 text-xs font-medium text-tc-darker hover:bg-tc-green/90 disabled:opacity-50"
                    >
                      Approve
                    </button>
                  )}
                  {mod.review_status !== "rejected" && (
                    <button
                      onClick={() => review(mod, "reject")}
                      disabled={busy !== null || !(notes[mod.slug] ?? "").trim()}
                      className="rounded border border-red-500/50 px-3 py-1 text-xs text-red-300 hover:bg-red-500/10 disabled:opacity-50"
                    >
                      Reject
                    </button>
                  )}
                  {mod.published && (
                    <button
                      onClick={() => review(mod, "unpublish")}
                      disabled={busy !== null}
                      className="rounded border border-tc-border/50 px-3 py-1 text-xs text-tc-text-dim hover:text-white disabled:opacity-50"
                    >
                      Unpublish
                    </button>
                  )}
                  <button
                    onClick={() => checkSources(mod.slug)}
                    disabled={busy !== null}
                    className="text-xs text-tc-text-dim hover:text-tc-green disabled:opacity-50"
                  >
                    {busy === `${mod.slug}:check` ? "Checking..." : "Check source"}
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
