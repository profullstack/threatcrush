"use client";

import { useState } from "react";
import Link from "next/link";
import ScrollReveal from "@/components/ScrollReveal";

interface ModuleMeta {
  name: string;
  display_name: string;
  description: string;
  long_description: string;
  logo_url: string;
  banner_url: string;
  screenshot_url: string;
  tags: string[];
  version: string;
  license: string;
  homepage_url: string;
  git_url: string;
  author_name: string;
}

const CATEGORIES = ["security", "monitoring", "scanning", "network", "compliance", "other"];

export default function PublishClient() {
  const [gitUrl, setGitUrl] = useState("");
  const [webUrl, setWebUrl] = useState("");
  const [fetching, setFetching] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [published, setPublished] = useState(false);
  const [error, setError] = useState("");

  // Editable fields
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("security");
  const [tags, setTags] = useState("");
  const [version, setVersion] = useState("0.1.0");
  const [license, setLicense] = useState("MIT");
  const [authorName, setAuthorName] = useState("");
  const [authorEmail, setAuthorEmail] = useState("");
  const [logoUrl, setLogoUrl] = useState("");
  const [pricingType, setPricingType] = useState("free");
  const [priceUsd, setPriceUsd] = useState("");
  const [metaFetched, setMetaFetched] = useState(false);

  const handleFetchMeta = async () => {
    if (!gitUrl && !webUrl) {
      setError("Enter a GitHub repo URL or website URL");
      return;
    }
    setFetching(true);
    setError("");

    try {
      const res = await fetch("/api/modules/fetch-meta", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: webUrl || undefined,
          git_url: gitUrl || undefined,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to fetch metadata");
      }

      const meta: ModuleMeta = await res.json();

      if (meta.name) setName(meta.name);
      if (meta.display_name) setDisplayName(meta.display_name);
      if (meta.description) setDescription(meta.description);
      if (meta.tags?.length) setTags(meta.tags.join(", "));
      if (meta.version) setVersion(meta.version);
      if (meta.license) setLicense(meta.license);
      if (meta.author_name) setAuthorName(meta.author_name);
      if (meta.logo_url) setLogoUrl(meta.logo_url);
      if (meta.homepage_url && !webUrl) setWebUrl(meta.homepage_url);
      if (meta.git_url && !gitUrl) setGitUrl(meta.git_url);
      setMetaFetched(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch metadata");
    } finally {
      setFetching(false);
    }
  };

  const handlePublish = async () => {
    if (!name || !authorEmail) {
      setError("Name and author email are required");
      return;
    }
    setPublishing(true);
    setError("");

    try {
      const res = await fetch("/api/modules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          display_name: displayName || name,
          description,
          category,
          tags: tags.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean),
          version,
          license,
          author_name: authorName,
          author_email: authorEmail,
          logo_url: logoUrl,
          homepage_url: webUrl,
          git_url: gitUrl,
          pricing_type: pricingType,
          price_usd: pricingType === "paid" ? parseFloat(priceUsd) || null : null,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to publish");
      }

      setPublished(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to publish");
    } finally {
      setPublishing(false);
    }
  };

  if (published) {
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    return (
      <>
        <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <Link href="/" className="text-xl font-bold text-tc-green glow-green font-mono">⚡ ThreatCrush</Link>
          </div>
        </nav>
        <main className="pt-24 pb-16 min-h-screen flex items-center justify-center">
          <div className="text-center">
            <p className="text-5xl mb-4">🎉</p>
            <h1 className="text-2xl font-bold text-white mb-2">Module Published!</h1>
            <p className="text-tc-text-dim mb-6">Your module is now live in the store.</p>
            <Link
              href={`/store/${slug}`}
              className="rounded-lg bg-tc-green px-6 py-3 font-bold text-black hover:bg-tc-green-dim transition-all"
            >
              View Module →
            </Link>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <Link href="/" className="text-xl font-bold text-tc-green glow-green font-mono">⚡ ThreatCrush</Link>
          <div className="hidden sm:flex items-center gap-6 text-sm text-tc-text-dim">
            <Link href="/store" className="hover:text-tc-green transition-colors">← Back to Store</Link>
          </div>
        </div>
      </nav>

      <main className="pt-24 pb-16 min-h-screen">
        <div className="mx-auto max-w-2xl px-6">
          <ScrollReveal>
            <div className="text-center mb-10">
              <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">// PUBLISH</p>
              <h1 className="text-3xl font-bold text-white mb-3">
                Publish a <span className="text-tc-green glow-green">Module</span>
              </h1>
              <p className="text-tc-text-dim text-sm">
                Paste a GitHub repo URL or website URL to auto-fetch metadata, then review and publish.
              </p>
              <p className="text-xs text-tc-text-dim mt-3">
                Need a starter? Clone the boilerplate from{" "}
                <a
                  href="https://github.com/profullstack/threatcrush/tree/master/boilerplates/module-example"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-tc-green hover:underline"
                >
                  /boilerplates/module-example
                </a>
                .
              </p>
            </div>
          </ScrollReveal>

          <ScrollReveal delay={50}>
            <div className="rounded-xl border border-tc-border bg-tc-card p-6 mb-6">
              <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <span className="text-tc-green font-mono">01</span> Enter URL
              </h2>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs text-tc-text-dim mb-1">GitHub Repo URL</label>
                  <input
                    type="url"
                    placeholder="https://github.com/owner/repo"
                    value={gitUrl}
                    onChange={(e) => setGitUrl(e.target.value)}
                    className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2.5 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs text-tc-text-dim mb-1">Or Website URL</label>
                  <input
                    type="url"
                    placeholder="https://mymodule.dev"
                    value={webUrl}
                    onChange={(e) => setWebUrl(e.target.value)}
                    className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2.5 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none font-mono"
                  />
                </div>

                <button
                  onClick={handleFetchMeta}
                  disabled={fetching || (!gitUrl && !webUrl)}
                  className="w-full rounded-lg border border-tc-green/30 bg-tc-green/5 px-4 py-2.5 text-sm font-medium text-tc-green hover:bg-tc-green/10 disabled:opacity-50 transition-all"
                >
                  {fetching ? "Fetching metadata..." : "🔍 Fetch Metadata"}
                </button>
              </div>
            </div>
          </ScrollReveal>

          <ScrollReveal delay={100}>
            <div className="rounded-xl border border-tc-border bg-tc-card p-6 mb-6">
              <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <span className="text-tc-green font-mono">02</span> Module Details
                {metaFetched && <span className="text-[10px] text-tc-green bg-tc-green/10 px-2 py-0.5 rounded-full">auto-filled</span>}
              </h2>

              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Name *</label>
                    <input
                      type="text"
                      placeholder="my-module"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Display Name</label>
                    <input
                      type="text"
                      placeholder="My Module"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-tc-text-dim mb-1">Description</label>
                  <textarea
                    placeholder="What does this module do?"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={2}
                    className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none resize-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Category</label>
                    <select
                      value={category}
                      onChange={(e) => setCategory(e.target.value)}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text focus:border-tc-green/50 focus:outline-none"
                    >
                      {CATEGORIES.map((c) => (
                        <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Version</label>
                    <input
                      type="text"
                      placeholder="0.1.0"
                      value={version}
                      onChange={(e) => setVersion(e.target.value)}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-tc-text-dim mb-1">Tags (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="security, scanner, network"
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                    className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">License</label>
                    <input
                      type="text"
                      placeholder="MIT"
                      value={license}
                      onChange={(e) => setLicense(e.target.value)}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Pricing</label>
                    <select
                      value={pricingType}
                      onChange={(e) => setPricingType(e.target.value)}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text focus:border-tc-green/50 focus:outline-none"
                    >
                      <option value="free">Free</option>
                      <option value="freemium">Freemium</option>
                      <option value="paid">Paid</option>
                    </select>
                  </div>
                </div>

                {pricingType === "paid" && (
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Price (USD)</label>
                    <input
                      type="number"
                      placeholder="9.99"
                      value={priceUsd}
                      onChange={(e) => setPriceUsd(e.target.value)}
                      min="0"
                      step="0.01"
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none font-mono"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-xs text-tc-text-dim mb-1">Logo URL</label>
                  <input
                    type="url"
                    placeholder="https://..."
                    value={logoUrl}
                    onChange={(e) => setLogoUrl(e.target.value)}
                    className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none font-mono"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Author Name</label>
                    <input
                      type="text"
                      placeholder="Your name"
                      value={authorName}
                      onChange={(e) => setAuthorName(e.target.value)}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-tc-text-dim mb-1">Author Email *</label>
                    <input
                      type="email"
                      placeholder="you@example.com"
                      value={authorEmail}
                      onChange={(e) => setAuthorEmail(e.target.value)}
                      required
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-sm text-tc-text placeholder-tc-text-dim focus:border-tc-green/50 focus:outline-none"
                    />
                  </div>
                </div>
              </div>
            </div>
          </ScrollReveal>

          {name && (
            <ScrollReveal delay={150}>
              <div className="rounded-xl border border-tc-border bg-tc-card p-6 mb-6">
                <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                  <span className="text-tc-green font-mono">03</span> Preview
                </h2>

                <div className="rounded-xl border border-tc-border bg-tc-darker p-5">
                  <div className="flex items-start gap-3 mb-3">
                    <div className="w-10 h-10 rounded-lg bg-tc-green/10 border border-tc-green/20 flex items-center justify-center flex-shrink-0 overflow-hidden">
                      {logoUrl ? (
                        <img src={logoUrl} alt={displayName || name} className="w-full h-full object-cover rounded-lg" />
                      ) : (
                        <span className="text-tc-green text-lg">📦</span>
                      )}
                    </div>
                    <div className="flex-1">
                      <h3 className="text-sm font-bold text-white">{displayName || name}</h3>
                      <p className="text-[10px] text-tc-text-dim font-mono">v{version}</p>
                    </div>
                    <span className="rounded-full bg-tc-green/10 border border-tc-green/30 px-2 py-0.5 text-[10px] font-bold text-tc-green uppercase">
                      {pricingType === "paid" ? `$${priceUsd || "0"}` : pricingType}
                    </span>
                  </div>
                  <p className="text-xs text-tc-text-dim">{description || "No description"}</p>
                  {tags && (
                    <div className="flex gap-1 mt-3 flex-wrap">
                      {tags.split(",").filter(Boolean).slice(0, 3).map((tag) => (
                        <span key={tag.trim()} className="rounded-full bg-tc-card px-2 py-0.5 text-[9px] text-tc-text-dim border border-tc-border">
                          {tag.trim()}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </ScrollReveal>
          )}

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400 mb-6">
              {error}
            </div>
          )}

          <ScrollReveal delay={200}>
            <button
              onClick={handlePublish}
              disabled={publishing || !name || !authorEmail}
              className="w-full rounded-xl bg-tc-green py-4 text-lg font-bold text-black transition-all hover:bg-tc-green-dim disabled:opacity-50 pulse-glow"
            >
              {publishing ? "Publishing..." : "🚀 Publish Module"}
            </button>
          </ScrollReveal>
        </div>
      </main>
    </>
  );
}
