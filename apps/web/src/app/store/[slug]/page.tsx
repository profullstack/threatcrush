"use client";

import { useState, useEffect, use } from "react";
import Link from "next/link";
import ScrollReveal from "@/components/ScrollReveal";
import { authHeaders } from "@/lib/auth-client";
import { useAuth } from "@/lib/auth-context";
import { decryptClientSecret, encryptClientSecret, isE2ESecret } from "@/lib/client-secret-crypto";
import { renderSanitizedMarkdown } from "@/lib/simple-markdown";
import type { PluginConfigField } from "@profullstack/pluginstore";

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
  config_schema: PluginConfigField[];
  config_notes: string | null;
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
  // long_description is author-supplied; renderSanitizedMarkdown escapes it before
  // building any markup (TC-04 / TC-39).
  return (
    <div
      className="prose-tc"
      dangerouslySetInnerHTML={{ __html: renderSanitizedMarkdown(content) }}
    />
  );
}

export default function ModuleDetailPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = use(params);
  const { signedIn, profile } = useAuth();
  const [mod, setMod] = useState<Module | null>(null);
  const [versions, setVersions] = useState<Version[]>([]);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [copied, setCopied] = useState(false);
  const [installed, setInstalled] = useState(false);
  const [settings, setSettings] = useState<{
    plain: Record<string, string | number | boolean | null>;
    secrets: Record<string, { isSet: boolean; length?: number; e2eEncrypted?: boolean }>;
    cryptoConfigured: boolean;
  } | null>(null);
  const [plainDrafts, setPlainDrafts] = useState<Record<string, string | boolean>>({});
  const [secretDrafts, setSecretDrafts] = useState<Record<string, string | null>>({});
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, string>>({});
  const [revealingSecrets, setRevealingSecrets] = useState<Record<string, boolean>>({});
  const [copiedSecret, setCopiedSecret] = useState<string | null>(null);
  const [savingConfig, setSavingConfig] = useState(false);
  const [configSaved, setConfigSaved] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);

  // Review form
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

  useEffect(() => {
    if (!signedIn) return;
    async function loadUserModuleState() {
      try {
        const [installedRes, settingsRes] = await Promise.all([
          fetch("/api/modules/installed", { headers: authHeaders(), cache: "no-store" }),
          fetch("/api/settings", { headers: authHeaders(), cache: "no-store" }),
        ]);

        if (installedRes.ok) {
          const data = await installedRes.json();
          setInstalled((data.installed || []).some((row: { module_slug: string; status: string }) =>
            row.module_slug === slug && row.status !== "removed"
          ));
        }

        if (settingsRes.ok) {
          setSettings(await settingsRes.json());
        }
      } catch {
        // keep the public module page usable even if account state fails
      }
    }
    loadUserModuleState();
  }, [signedIn, slug]);

  const handleInstall = async () => {
    if (!mod) return;
    setInstalling(true);
    try {
      await fetch(`/api/modules/${mod.slug}/install`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ platform: "web" }),
      });
      setInstalled(signedIn);
    } catch { /* ignore */ }
    setInstalling(false);
  };

  const handleCopy = () => {
    if (!mod) return;
    navigator.clipboard?.writeText(`threatcrush modules install ${mod.slug}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const fieldValue = (field: PluginConfigField) => {
    const existing = settings?.plain?.[field.key];
    if (plainDrafts[field.key] !== undefined) return plainDrafts[field.key];
    if (existing !== undefined && existing !== null) return existing;
    if (field.default !== undefined && field.default !== null) return field.default;
    return field.type === "boolean" ? false : "";
  };

  const saveConfig = async () => {
    if (!mod) return;
    setSavingConfig(true);
    setConfigSaved(false);
    setConfigError(null);

    if (!profile?.id) {
      setConfigError("Account profile is still loading");
      setSavingConfig(false);
      return;
    }

    const plain: Record<string, string | number | boolean | null> = {};
    const secrets: Record<string, string | null> = {};

    for (const field of mod.config_schema || []) {
      if (field.type === "secret") {
        if (secretDrafts[field.key] !== undefined) {
          const draft = secretDrafts[field.key];
          secrets[field.key] = draft === null
            ? null
            : draft.trim()
              ? await encryptClientSecret(profile.id, draft.trim())
              : "";
        }
        continue;
      }

      const value = fieldValue(field);
      if (field.type === "number") {
        const n = Number(value);
        plain[field.key] = Number.isFinite(n) ? n : null;
      } else if (field.type === "boolean") {
        plain[field.key] = value === true || value === "true";
      } else {
        const text = String(value || "").trim();
        plain[field.key] = text || null;
      }
    }

    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ plain, secrets }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to save settings");
      setSettings(data);
      setSecretDrafts({});
      setConfigSaved(true);
    } catch (error) {
      setConfigError((error as Error).message);
    } finally {
      setSavingConfig(false);
    }
  };

  const revealSecret = async (key: string) => {
    if (!profile?.id) {
      setConfigError("Account profile is still loading");
      return;
    }

    setConfigError(null);
    setRevealingSecrets((state) => ({ ...state, [key]: true }));
    try {
      const res = await fetch(`/api/settings?revealSecret=${encodeURIComponent(key)}`, {
        headers: authHeaders(),
        cache: "no-store",
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to load secret");

      const stored = data.secretValues?.[key];
      if (typeof stored !== "string" || !stored) throw new Error("No saved secret found");

      const value = await decryptClientSecret(profile.id, stored);
      setRevealedSecrets((state) => ({ ...state, [key]: value }));

      if (!isE2ESecret(stored)) {
        const encrypted = await encryptClientSecret(profile.id, value);
        const upgradeRes = await fetch("/api/settings", {
          method: "PUT",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ secrets: { [key]: encrypted } }),
        });
        if (upgradeRes.ok) setSettings(await upgradeRes.json());
      }
    } catch (error) {
      setConfigError((error as Error).message);
    } finally {
      setRevealingSecrets((state) => ({ ...state, [key]: false }));
    }
  };

  const copyRevealedSecret = async (key: string) => {
    const value = revealedSecrets[key];
    if (!value) return;
    await navigator.clipboard?.writeText(value);
    setCopiedSecret(key);
    setTimeout(() => setCopiedSecret(null), 2000);
  };

  const handleReviewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mod || !profile?.email) return;
    setSubmittingReview(true);
    try {
      const res = await fetch(`/api/modules/${mod.slug}/review`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
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
            <img src="/logo.svg" alt="ThreatCrush" className="h-12 w-auto sm:h-14" />
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
                    <span className="text-tc-green">threatcrush modules install {mod.slug}</span>
                    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-tc-text-dim text-xs">
                      {copied ? "✓ copied" : "📋"}
                    </span>
                  </div>

                  <button
                    onClick={handleInstall}
                    disabled={installing}
                    className="rounded-lg bg-tc-green px-6 py-3 text-sm font-bold text-black transition-all hover:bg-tc-green-dim disabled:opacity-50"
                  >
                    {installing ? "Installing..." : installed ? "Installed" : "Install"}
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
              {mod.config_schema && mod.config_schema.length > 0 && (
                <ScrollReveal delay={75}>
                  <div className="rounded-xl border border-tc-border bg-tc-card p-6">
                    <h2 className="text-lg font-bold text-white mb-4">Configuration</h2>
                    {!signedIn ? (
                      <p className="text-sm text-tc-text-dim">
                        <Link href="/auth/login" className="text-tc-green hover:underline">Log in</Link>{" "}
                        to install and configure this module.
                      </p>
                    ) : (
                      <div className="space-y-4">
                        {!installed && (
                          <button
                            onClick={handleInstall}
                            disabled={installing}
                            className="rounded-lg bg-tc-green px-4 py-2 text-xs font-bold text-black hover:bg-tc-green-dim disabled:opacity-50"
                          >
                            {installing ? "Installing..." : "Install for my account"}
                          </button>
                        )}
                        {mod.config_notes && (
                          <p className="text-xs text-tc-text-dim leading-relaxed">{mod.config_notes}</p>
                        )}
                        <div className="space-y-3">
                          {mod.config_schema.map((field) => {
                            const savedSecret = settings?.secrets?.[field.key];
                            if (field.type === "secret") {
                              return (
                                <div key={field.key}>
                                  <label className="block text-xs font-semibold text-tc-text mb-1">
                                    {field.label}
                                    <span className="ml-2 font-mono text-[10px] text-tc-text-dim">{field.key}</span>
                                  </label>
                                  <div className="flex flex-col gap-2 sm:flex-row">
                                    <input
                                      type="password"
                                      value={secretDrafts[field.key] || ""}
                                      placeholder={savedSecret?.isSet ? "Saved secret set" : field.placeholder || ""}
                                      onChange={(e) => setSecretDrafts((drafts) => ({ ...drafts, [field.key]: e.target.value }))}
                                      className="flex-1 rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                                    />
                                    {savedSecret?.isSet && (
                                      <>
                                        <button
                                          type="button"
                                          onClick={() => revealSecret(field.key)}
                                          disabled={!!revealingSecrets[field.key]}
                                          className="rounded-lg border border-tc-border px-3 py-2 text-xs text-tc-text-dim hover:border-tc-green/40 hover:text-tc-green disabled:opacity-50"
                                        >
                                          {revealingSecrets[field.key] ? "Decrypting..." : "Reveal"}
                                        </button>
                                        <button
                                          type="button"
                                          onClick={() => setSecretDrafts((drafts) => ({ ...drafts, [field.key]: null }))}
                                          className="rounded-lg border border-tc-border px-3 py-2 text-xs text-tc-text-dim hover:border-red-400/40 hover:text-red-400"
                                        >
                                          Clear
                                        </button>
                                      </>
                                    )}
                                  </div>
                                  {revealedSecrets[field.key] && (
                                    <div className="mt-2 flex flex-col gap-2 rounded-lg border border-tc-border bg-black/40 p-2 sm:flex-row">
                                      <input
                                        readOnly
                                        type="text"
                                        value={revealedSecrets[field.key]}
                                        className="flex-1 rounded border border-tc-border bg-tc-darker px-2 py-1.5 font-mono text-xs text-tc-text focus:outline-none"
                                      />
                                      <button
                                        type="button"
                                        onClick={() => copyRevealedSecret(field.key)}
                                        className="rounded border border-tc-border px-3 py-1.5 text-xs text-tc-text-dim hover:border-tc-green/40 hover:text-tc-green"
                                      >
                                        {copiedSecret === field.key ? "Copied" : "Copy"}
                                      </button>
                                    </div>
                                  )}
                                  {savedSecret?.isSet && (
                                    <p className="mt-1 text-[11px] text-tc-text-dim">
                                      {savedSecret.e2eEncrypted ? "E2E encrypted in this browser." : "Legacy secret; reveal once to upgrade it to E2E encryption."}
                                    </p>
                                  )}
                                  {field.help && <p className="mt-1 text-[11px] text-tc-text-dim">{field.help}</p>}
                                </div>
                              );
                            }

                            if (field.type === "boolean") {
                              return (
                                <label key={field.key} className="flex items-center justify-between gap-3 rounded-lg border border-tc-border bg-tc-darker px-3 py-2">
                                  <span className="text-sm text-tc-text">
                                    {field.label}
                                    <span className="ml-2 font-mono text-[10px] text-tc-text-dim">{field.key}</span>
                                  </span>
                                  <input
                                    type="checkbox"
                                    checked={!!fieldValue(field)}
                                    onChange={(e) => setPlainDrafts((drafts) => ({ ...drafts, [field.key]: e.target.checked }))}
                                    className="h-4 w-4 accent-tc-green"
                                  />
                                </label>
                              );
                            }

                            return (
                              <div key={field.key}>
                                <label className="block text-xs font-semibold text-tc-text mb-1">
                                  {field.label}
                                  <span className="ml-2 font-mono text-[10px] text-tc-text-dim">{field.key}</span>
                                </label>
                                <input
                                  type={field.type === "number" ? "number" : field.type === "url" ? "url" : "text"}
                                  value={String(fieldValue(field))}
                                  placeholder={field.placeholder || ""}
                                  onChange={(e) => setPlainDrafts((drafts) => ({ ...drafts, [field.key]: e.target.value }))}
                                  className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                                />
                                {field.help && <p className="mt-1 text-[11px] text-tc-text-dim">{field.help}</p>}
                              </div>
                            );
                          })}
                        </div>
                        <div className="flex items-center gap-3">
                          <button
                            onClick={saveConfig}
                            disabled={savingConfig || !installed}
                            className="rounded-lg bg-tc-green px-4 py-2 text-xs font-bold text-black hover:bg-tc-green-dim disabled:opacity-50"
                          >
                            {savingConfig ? "Saving..." : "Save configuration"}
                          </button>
                          {configSaved && <span className="text-xs text-tc-green">Saved</span>}
                          {configError && <span className="text-xs text-red-400">{configError}</span>}
                        </div>
                      </div>
                    )}
                  </div>
                </ScrollReveal>
              )}

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
                      placeholder="Log in to leave a review"
                      value={profile?.email ?? ""}
                      readOnly
                      disabled={!signedIn}
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
                      disabled={submittingReview || !profile?.email}
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
