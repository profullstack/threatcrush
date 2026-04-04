"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import ScrollReveal from "@/components/ScrollReveal";

interface Module {
  id: string;
  slug: string;
  name: string;
  display_name: string;
  description: string;
  logo_url: string;
  category: string;
  tags: string[];
  downloads: number;
  rating_avg: number;
  rating_count: number;
  pricing_type: string;
  price_usd: number | null;
  version: string;
  verified: boolean;
  featured: boolean;
}

const CATEGORIES = [
  { value: "all", label: "All" },
  { value: "security", label: "Security" },
  { value: "monitoring", label: "Monitoring" },
  { value: "scanning", label: "Scanning" },
  { value: "network", label: "Network" },
  { value: "compliance", label: "Compliance" },
  { value: "other", label: "Other" },
];

const SORTS = [
  { value: "popular", label: "Popular" },
  { value: "newest", label: "Newest" },
  { value: "top-rated", label: "Top Rated" },
];

function StarRating({ rating }: { rating: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((star) => (
        <span
          key={star}
          className={`text-xs ${
            star <= Math.round(rating) ? "text-yellow-400" : "text-tc-border"
          }`}
        >
          ★
        </span>
      ))}
    </div>
  );
}

function PriceBadge({ type, price }: { type: string; price: number | null }) {
  if (type === "free") {
    return (
      <span className="rounded-full bg-tc-green/10 border border-tc-green/30 px-2 py-0.5 text-[10px] font-bold text-tc-green">
        FREE
      </span>
    );
  }
  if (type === "freemium") {
    return (
      <span className="rounded-full bg-yellow-400/10 border border-yellow-400/30 px-2 py-0.5 text-[10px] font-bold text-yellow-400">
        FREEMIUM
      </span>
    );
  }
  return (
    <span className="rounded-full bg-blue-400/10 border border-blue-400/30 px-2 py-0.5 text-[10px] font-bold text-blue-400">
      ${price?.toFixed(2) || "—"}
    </span>
  );
}

export default function StoreContent() {
  const [modules, setModules] = useState<Module[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [sort, setSort] = useState("popular");
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const fetchModules = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        limit: "20",
        sort,
      });
      if (search) params.set("search", search);
      if (category !== "all") params.set("category", category);

      const res = await fetch(`/api/modules?${params}`);
      const data = await res.json();
      setModules(data.modules || []);
      setTotalPages(data.totalPages || 1);
    } catch {
      setModules([]);
    } finally {
      setLoading(false);
    }
  }, [search, category, sort, page]);

  useEffect(() => {
    const timer = setTimeout(fetchModules, 300);
    return () => clearTimeout(timer);
  }, [fetchModules]);

  return (
    <>
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-xl font-bold text-tc-green glow-green font-mono">
              ⚡ ThreatCrush
            </span>
          </Link>
          <div className="hidden sm:flex items-center gap-6 text-sm text-tc-text-dim">
            <Link href="/" className="hover:text-tc-green transition-colors">Home</Link>
            <Link href="/store" className="text-tc-green">Module Store</Link>
            <Link
              href="/store/publish"
              className="rounded-lg bg-tc-green px-4 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim"
            >
              Publish Module
            </Link>
          </div>
        </div>
      </nav>

      <main className="pt-24 pb-16 min-h-screen">
        <div className="mx-auto max-w-6xl px-6">
          {/* Header */}
          <ScrollReveal>
            <div className="text-center mb-12">
              <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">
                // MODULE STORE
              </p>
              <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4">
                Extend <span className="text-tc-green glow-green">ThreatCrush</span>
              </h1>
              <p className="text-tc-text-dim max-w-xl mx-auto">
                Browse community modules to add new capabilities — scanning, monitoring, compliance, and more.
              </p>
            </div>
          </ScrollReveal>

          {/* Filters */}
          <ScrollReveal delay={100}>
            <div className="flex flex-col sm:flex-row gap-4 mb-8">
              {/* Search */}
              <div className="flex-1">
                <input
                  type="text"
                  placeholder="Search modules..."
                  value={search}
                  onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                  className="w-full rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none transition-colors font-mono text-sm"
                />
              </div>

              {/* Category */}
              <div className="flex gap-2 flex-wrap">
                {CATEGORIES.map((cat) => (
                  <button
                    key={cat.value}
                    onClick={() => { setCategory(cat.value); setPage(1); }}
                    className={`rounded-lg px-3 py-2 text-xs font-medium transition-all ${
                      category === cat.value
                        ? "bg-tc-green/10 border border-tc-green/30 text-tc-green"
                        : "border border-tc-border text-tc-text-dim hover:border-tc-green/20 hover:text-tc-text"
                    }`}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>
            </div>
          </ScrollReveal>

          {/* Sort */}
          <ScrollReveal delay={150}>
            <div className="flex items-center gap-2 mb-6">
              <span className="text-xs text-tc-text-dim">Sort:</span>
              {SORTS.map((s) => (
                <button
                  key={s.value}
                  onClick={() => { setSort(s.value); setPage(1); }}
                  className={`text-xs px-2 py-1 rounded transition-all ${
                    sort === s.value
                      ? "text-tc-green font-bold"
                      : "text-tc-text-dim hover:text-tc-text"
                  }`}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </ScrollReveal>

          {/* Module Grid */}
          {loading ? (
            <div className="text-center py-20">
              <p className="text-tc-text-dim font-mono">Loading modules...</p>
            </div>
          ) : modules.length === 0 ? (
            <div className="text-center py-20">
              <p className="text-4xl mb-4">📦</p>
              <p className="text-tc-text-dim font-mono mb-2">No modules found</p>
              <p className="text-sm text-tc-text-dim">
                Be the first to{" "}
                <Link href="/store/publish" className="text-tc-green hover:underline">
                  publish a module
                </Link>
                !
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
              {modules.map((mod, i) => (
                <ScrollReveal key={mod.id} delay={i * 50}>
                  <Link href={`/store/${mod.slug}`}>
                    <div className="group rounded-xl border border-tc-border bg-tc-card p-5 transition-all hover:border-tc-green/30 glow-box-hover h-full cursor-pointer">
                      <div className="flex items-start gap-3 mb-3">
                        {/* Logo */}
                        <div className="w-10 h-10 rounded-lg bg-tc-green/10 border border-tc-green/20 flex items-center justify-center flex-shrink-0 overflow-hidden">
                          {mod.logo_url ? (
                            <img
                              src={mod.logo_url}
                              alt={mod.display_name}
                              className="w-full h-full object-cover rounded-lg"
                            />
                          ) : (
                            <span className="text-tc-green text-lg">📦</span>
                          )}
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <h3 className="text-sm font-bold text-white group-hover:text-tc-green transition-colors truncate">
                              {mod.display_name}
                            </h3>
                            {mod.verified && (
                              <span className="text-tc-green text-xs" title="Verified">✓</span>
                            )}
                          </div>
                          <p className="text-[10px] text-tc-text-dim font-mono">
                            v{mod.version}
                          </p>
                        </div>

                        <PriceBadge type={mod.pricing_type} price={mod.price_usd} />
                      </div>

                      <p className="text-xs text-tc-text-dim leading-relaxed mb-3 line-clamp-2">
                        {mod.description || "No description provided."}
                      </p>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <StarRating rating={mod.rating_avg} />
                          <span className="text-[10px] text-tc-text-dim">
                            ({mod.rating_count})
                          </span>
                        </div>
                        <span className="text-[10px] text-tc-text-dim font-mono">
                          ↓ {mod.downloads.toLocaleString()}
                        </span>
                      </div>

                      {mod.tags && mod.tags.length > 0 && (
                        <div className="flex gap-1 mt-3 flex-wrap">
                          {mod.tags.slice(0, 3).map((tag) => (
                            <span
                              key={tag}
                              className="rounded-full bg-tc-darker px-2 py-0.5 text-[9px] text-tc-text-dim border border-tc-border"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </Link>
                </ScrollReveal>
              ))}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-center gap-2 mt-10">
              <button
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="rounded-lg border border-tc-border px-3 py-2 text-xs text-tc-text-dim hover:border-tc-green/30 disabled:opacity-30 transition-all"
              >
                ← Prev
              </button>
              <span className="flex items-center px-3 text-xs text-tc-text-dim font-mono">
                {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page === totalPages}
                className="rounded-lg border border-tc-border px-3 py-2 text-xs text-tc-text-dim hover:border-tc-green/30 disabled:opacity-30 transition-all"
              >
                Next →
              </button>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-tc-border py-8">
        <div className="mx-auto max-w-6xl px-6 flex items-center justify-between">
          <Link href="/" className="font-mono text-tc-green font-bold text-sm">⚡ ThreatCrush</Link>
          <p className="text-xs text-tc-text-dim">© {new Date().getFullYear()} ThreatCrush</p>
        </div>
      </footer>
    </>
  );
}
