"use client";

import { useState, useEffect, use } from "react";
import Link from "next/link";
import ScrollReveal from "@/components/ScrollReveal";

interface Module {
  id: string;
  slug: string;
  name: string;
  display_name: string;
  description: string;
  long_description: string;
  logo_url: string;
  banner_url: string;
  screenshot_url: string;
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
  license: string;
  homepage_url: string;
  git_url: string;
  author_name: string;
  author_email: string;
  os_support: string[];
  capabilities: string[];
  created_at: string;
  updated_at: string;
}

interface Version {
  id: string;
  version: string;
  changelog: string;
  git_tag: string;
  created_at: string;
}

interface Review {
  id: string;
  user_email: string;
  rating: number;
  title: string;
  body: string;
  created_at: string;
}

function StarRating({ rating, size = "sm" }: { rating: number; size?: string }) {
  const starClass = size === "lg" ? "text-lg" : "text-xs";
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((star) => (
        <span
          key={star}
          className={`${starClass} ${
            star <= Math.round(rating) ? "text-yellow-400" : "text-tc-border"
          }`}
        >
          ★
        </span>
      ))}
    </div>
  );
}

function SimpleMarkdown({ content }: { content: string }) {
  // Very basic markdown rendering: headers, bold, code blocks, links, lists
  const lines = content.split("\n");
  const html = lines
    .map((line) => {
      // Headers
      if (line.startsWith("### ")) return `<h3 class="text-lg font-bold text-white mt-6 mb-2">${line.slice(4)}</h3>`;
      if (line.startsWith("## ")) return `<h2 class="text-xl font-bold text-white mt-8 mb-3">${line.slice(3)}</h2>`;
      if (line.startsWith("# ")) return `<h1 class="text-2xl font-bold text-white mt-8 mb-4">${line.slice(2)}</h1>`;
      // Code blocks (inline)
      let processed = line.replace(/`([^`]+)`/g, '<code class="bg-tc-darker px-1.5 py-0.5 rounded text-tc-green text-xs font-mono">$1</code>');
      // Bold
      processed = processed.replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white font-bold">$1</strong>');
      // Links
      processed = processed.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener" class="text-tc-green hover:underline">$1</a>');
      // List items
      if (processed.startsWith("- ") || processed.startsWith("* ")) {
        return `<li class="ml-4 text-tc-text-dim text-sm leading-relaxed list-disc">${processed.slice(2)}</li>`;
      }
      // Empty line
      if (!processed.trim()) return '<br/>';
      return `<p class="text-tc-text-dim text-sm leading-relaxed">${processed}</p>`;
    })
    .join("\n");

  return (
    <div
      className="prose-tc"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

export default function ModuleDetailPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = use(params);
  const [mod, setMod] = useState<Module | null>(null);
  const [versions, setVersions] = useState<Version[]>([]);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [copied, setCopied] = useState(false);

  // Review form
  const [reviewEmail, setReviewEmail] = useState("");
  const [reviewRating, setReviewRating] = useState(5);
  const [reviewBody, setReviewBody] = useState("");
  const [submittingReview, setSubmittingReview] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch(`/api/modules/${slug}`);
        if (!res.ok) throw new Error("Not found");
        const data = await res.json();
        setMod(data.module);
        setVersions(data.versions || []);
        setReviews(data.reviews || []);
      } catch {
        setMod(null);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [slug]);

  const handleInstall = async () => {
    if (!mod) return;
    setInstalling(true);
    try {
      await fetch(`/api/modules/${mod.slug}/install`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ platform: "web" }),
      });
    } catch { /* ignore */ }
    setInstalling(false);
  };

  const handleCopy = () => {
    if (!mod) return;
    navigator.clipboard?.writeText(`threatcrush install ${mod.name}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleReviewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mod || !reviewEmail) return;
    setSubmittingReview(true);
    try {
      const res = await fetch(`/api/modules/${mod.slug}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_email: reviewEmail,
          rating: reviewRating,
          body: reviewBody,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setReviews([data.review, ...reviews]);
        setReviewBody("");
      }
    } catch { /* ignore */ }
    setSubmittingReview(false);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-tc-text-dim font-mono">Loading...</p>
      </div>
    );
  }

  if (!mod) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <p className="text-4xl">404</p>
        <p className="text-tc-text-dim font-mono">Module not found</p>
        <Link href="/store" className="text-tc-green hover:underline text-sm">
          ← Back to Store
        </Link>
      </div>
    );
  }

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
            <Link href="/store" className="hover:text-tc-green transition-colors">Module Store</Link>
          </div>
        </div>
      </nav>

      <main className="pt-24 pb-16 min-h-screen">
        <div className="mx-auto max-w-4xl px-6">
          {/* Breadcrumb */}
          <ScrollReveal>
            <div className="flex items-center gap-2 text-xs text-tc-text-dim mb-8 font-mono">
              <Link href="/store" className="hover:text-tc-green">Store</Link>
              <span>/</span>
              <span className="text-tc-text">{mod.display_name}</span>
            </div>
          </ScrollReveal>

          {/* Module Header */}
          <ScrollReveal delay={50}>
            <div className="rounded-xl border border-tc-border bg-tc-card p-6 sm:p-8 mb-8">
              <div className="flex flex-col sm:flex-row gap-6">
                {/* Logo */}
                <div className="w-20 h-20 rounded-xl bg-tc-green/10 border border-tc-green/20 flex items-center justify-center flex-shrink-0 overflow-hidden">
                  {mod.logo_url ? (
                    <img src={mod.logo_url} alt={mod.display_name} className="w-full h-full object-cover rounded-xl" />
                  ) : (
                    <span className="text-tc-green text-3xl">📦</span>
                  )}
                </div>

                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h1 className="text-2xl font-bold text-white">{mod.display_name}</h1>
                    {mod.verified && (
                      <span className="rounded-full bg-tc-green/10 border border-tc-green/30 px-2 py-0.5 text-[10px] text-tc-green">
                        ✓ Verified
                      </span>
                    )}
                  </div>

                  <p className="text-tc-text-dim text-sm mb-3">{mod.description}</p>

                  <div className="flex items-center gap-4 flex-wrap text-xs text-tc-text-dim">
                    <div className="flex items-center gap-1">
                      <StarRating rating={mod.rating_avg} />
                      <span>({mod.rating_count})</span>
                    </div>
                    <span>↓ {mod.downloads.toLocaleString()} downloads</span>
                    <span>v{mod.version}</span>
                    <span>{mod.license}</span>
                    {mod.author_name && <span>by {mod.author_name}</span>}
                  </div>
                </div>
              </div>

              {/* Install command */}
              <div className="mt-6 pt-6 border-t border-tc-border">
                <div className="flex flex-col sm:flex-row gap-3">
                  <div
                    className="group flex-1 relative rounded-lg bg-black/60 border border-tc-border px-4 py-3 font-mono text-sm cursor-pointer hover:border-tc-green/40 transition-all"
                    onClick={handleCopy}
                  >
                    <span className="text-tc-text-dim">$ </span>
                    <span className="text-tc-green">threatcrush install {mod.name}</span>
                    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs">
                      {copied ? "✓ copied" : "📋"}
                    </span>
                  </div>

                  <button
                    onClick={handleInstall}
                    disabled={installing}
                    className="rounded-lg bg-tc-green px-6 py-3 text-sm font-bold text-black transition-all hover:bg-tc-green-dim disabled:opacity-50"
                  >
                    {installing ? "Installing..." : "Install"}
                  </button>
                </div>

                {/* Links */}
                <div className="flex gap-3 mt-4">
                  {mod.git_url && (
                    <a
                      href={mod.git_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green transition-all"
                    >
                      <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
                      GitHub
                    </a>
                  )}
                  {mod.homepage_url && (
                    <a
                      href={mod.homepage_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-lg border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green transition-all"
                    >
                      🌐 Website
                    </a>
                  )}
                </div>
              </div>
            </div>
          </ScrollReveal>

          {/* Content Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Main: README / Description */}
            <div className="lg:col-span-2 space-y-8">
              {/* Long Description / README */}
              {mod.long_description && (
                <ScrollReveal delay={100}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-6">
                    <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <span>📖</span> README
                    </h2>
                    <SimpleMarkdown content={mod.long_description} />
                  </div>
                </ScrollReveal>
              )}

              {/* Screenshot */}
              {mod.screenshot_url && (
                <ScrollReveal delay={150}>
                  <div className="rounded-xl border border-tc-border overflow-hidden">
                    <img
                      src={mod.screenshot_url}
                      alt={`${mod.display_name} screenshot`}
                      className="w-full"
                    />
                  </div>
                </ScrollReveal>
              )}

              {/* Reviews */}
              <ScrollReveal delay={200}>
                <div className="rounded-xl border border-tc-border bg-tc-card p-6">
                  <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <span>⭐</span> Reviews ({reviews.length})
                  </h2>

                  {reviews.length === 0 ? (
                    <p className="text-sm text-tc-text-dim">No reviews yet. Be the first!</p>
                  ) : (
                    <div className="space-y-4 mb-6">
                      {reviews.map((review) => (
                        <div key={review.id} className="border-b border-tc-border pb-4 last:border-0">
                          <div className="flex items-center gap-2 mb-1">
                            <StarRating rating={review.rating} />
                            <span className="text-xs text-tc-text-dim">
                              {review.user_email.replace(/(.{2}).*(@.*)/, "$1***$2")}
                            </span>
                            <span className="text-xs text-tc-text-dim">
                              · {new Date(review.created_at).toLocaleDateString()}
                            </span>
                          </div>
                          {review.body && (
                            <p className="text-sm text-tc-text-dim mt-1">{review.body}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Review Form */}
                  <form onSubmit={handleReviewSubmit} className="border-t border-tc-border pt-4 space-y-3">
                    <h3 className="text-sm font-bold text-white">Leave a Review</h3>
                    <input
                      type="email"
                      placeholder="Your email"
                      value={reviewEmail}
                      onChange={(e) => setReviewEmail(e.target.value)}
                      required
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                    />
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-tc-text-dim">Rating:</span>
                      {[1, 2, 3, 4, 5].map((star) => (
                        <button
                          key={star}
                          type="button"
                          onClick={() => setReviewRating(star)}
                          className={`text-lg ${
                            star <= reviewRating ? "text-yellow-400" : "text-tc-border"
                          }`}
                        >
                          ★
                        </button>
                      ))}
                    </div>
                    <textarea
                      placeholder="Your review (optional)"
                      value={reviewBody}
                      onChange={(e) => setReviewBody(e.target.value)}
                      rows={3}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none resize-none"
                    />
                    <button
                      type="submit"
                      disabled={submittingReview || !reviewEmail}
                      className="rounded-lg bg-tc-green px-4 py-2 text-xs font-bold text-black hover:bg-tc-green-dim disabled:opacity-50 transition-all"
                    >
                      {submittingReview ? "Submitting..." : "Submit Review"}
                    </button>
                  </form>
                </div>
              </ScrollReveal>
            </div>

            {/* Sidebar */}
            <div className="space-y-6">
              {/* Info */}
              <ScrollReveal delay={100}>
                <div className="rounded-xl border border-tc-border bg-tc-card p-5">
                  <h3 className="text-sm font-bold text-white mb-3">Details</h3>
                  <dl className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-tc-text-dim">Category</dt>
                      <dd className="text-tc-text capitalize">{mod.category}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-tc-text-dim">License</dt>
                      <dd className="text-tc-text">{mod.license}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-tc-text-dim">Version</dt>
                      <dd className="text-tc-text font-mono">v{mod.version}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-tc-text-dim">Downloads</dt>
                      <dd className="text-tc-text">{mod.downloads.toLocaleString()}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-tc-text-dim">OS</dt>
                      <dd className="text-tc-text">{(mod.os_support || []).join(", ")}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-tc-text-dim">Published</dt>
                      <dd className="text-tc-text">{new Date(mod.created_at).toLocaleDateString()}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-tc-text-dim">Updated</dt>
                      <dd className="text-tc-text">{new Date(mod.updated_at).toLocaleDateString()}</dd>
                    </div>
                  </dl>
                </div>
              </ScrollReveal>

              {/* Tags */}
              {mod.tags && mod.tags.length > 0 && (
                <ScrollReveal delay={150}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-5">
                    <h3 className="text-sm font-bold text-white mb-3">Tags</h3>
                    <div className="flex gap-1.5 flex-wrap">
                      {mod.tags.map((tag) => (
                        <span
                          key={tag}
                          className="rounded-full bg-tc-darker px-2.5 py-1 text-[10px] text-tc-text-dim border border-tc-border"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </ScrollReveal>
              )}

              {/* Version History */}
              {versions.length > 0 && (
                <ScrollReveal delay={200}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-5">
                    <h3 className="text-sm font-bold text-white mb-3">Version History</h3>
                    <div className="space-y-3">
                      {versions.slice(0, 5).map((v) => (
                        <div key={v.id} className="border-b border-tc-border pb-2 last:border-0">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-mono text-tc-green">v{v.version}</span>
                            <span className="text-[10px] text-tc-text-dim">
                              {new Date(v.created_at).toLocaleDateString()}
                            </span>
                          </div>
                          {v.changelog && (
                            <p className="text-[10px] text-tc-text-dim mt-1">{v.changelog}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </ScrollReveal>
              )}
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
