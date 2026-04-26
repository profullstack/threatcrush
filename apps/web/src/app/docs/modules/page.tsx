import Link from "next/link";

const requiredMetadata = [
  "name",
  "display_name",
  "description",
  "version",
  "license",
  "author_name",
  "git_url or homepage_url",
];

const recommendedMetadata = [
  "logo_url",
  "banner_url",
  "screenshot_url",
  "tags",
  "homepage_url",
  "pricing_type",
  "price_usd (if paid)",
];

const supportedContributorPaths = [
  {
    title: "Web UI publish flow",
    description: "Use the publish page to paste a GitHub repo URL or website URL, auto-fetch metadata, review it, and submit.",
    href: "/store/publish",
    cta: "Open publish page",
  },
  {
    title: "CLI publish flow",
    description: "Run `threatcrush store publish <url>` to fetch metadata, preview it in the terminal, and publish the module.",
    href: "/docs",
    cta: "Back to CLI docs",
  },
  {
    title: "Store listing review",
    description: "Browse the live store and make sure your listing quality matches the marketplace expectations before publishing more modules.",
    href: "/store",
    cta: "Browse store",
  },
];

const apiEndpoints: Array<{
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  auth: "none" | "bearer" | "email";
  purpose: string;
}> = [
  { method: "GET",    path: "/api/modules",                       auth: "none",   purpose: "List / search / paginate published modules" },
  { method: "POST",   path: "/api/modules",                       auth: "bearer", purpose: "Publish a new module" },
  { method: "GET",    path: "/api/modules/{slug}",                auth: "none",   purpose: "Module detail + versions + recent reviews" },
  { method: "PATCH",  path: "/api/modules/{slug}",                auth: "email",  purpose: "Edit your module" },
  { method: "DELETE", path: "/api/modules/{slug}",                auth: "email",  purpose: "Remove your module" },
  { method: "GET",    path: "/api/modules/{slug}/install",        auth: "none",   purpose: "Read-only install info (does not count)" },
  { method: "POST",   path: "/api/modules/{slug}/install",        auth: "none",   purpose: "Install info + increment download count" },
  { method: "GET",    path: "/api/modules/{slug}/review",         auth: "none",   purpose: "List reviews (paginated)" },
  { method: "POST",   path: "/api/modules/{slug}/review",         auth: "email",  purpose: "Create / update your review (one per email)" },
  { method: "POST",   path: "/api/modules/fetch-meta",            auth: "none",   purpose: "Probe URL or GitHub repo for prefilled meta" },
];

const boilerplates = [
  {
    name: "module-example",
    description: "Minimal hello-world module that subscribes to daemon events.",
    href: "https://github.com/profullstack/threatcrush/tree/master/boilerplates/module-example",
  },
  {
    name: "free-module",
    description: "MIT-licensed fetch-loop API integration (URLhaus public feed) → emits ThreatEvents.",
    href: "https://github.com/profullstack/threatcrush/tree/master/boilerplates/free-module",
  },
  {
    name: "paid-module",
    description: "Paid template with login / logout / status CLI commands and a license-gated init.",
    href: "https://github.com/profullstack/threatcrush/tree/master/boilerplates/paid-module",
  },
];

const API_REFERENCE_URL =
  "https://github.com/profullstack/threatcrush/blob/master/docs/MODULE_STORE_API.md";

const plannedModuleFeatures = [
  "Fully documented SDK package with starter templates and stronger versioning guarantees",
  "Formal manifest spec for installable runtime modules",
  "Module install/remove/update lifecycle docs once the runtime side is complete",
  "More explicit review, moderation, and trust/safety policy for marketplace listings",
  "Richer pricing and billing docs for paid modules",
];

export default function DocsModulesPage() {
  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <div className="mx-auto max-w-5xl px-6 py-16">
        <div className="mb-12">
          <Link href="/docs" className="text-sm text-tc-green hover:underline">← Back to Docs</Link>
          <p className="mt-6 font-mono text-sm text-tc-green tracking-wider">// DOCS / MODULES</p>
          <h1 className="mt-3 text-4xl font-black text-white">Module Author Docs</h1>
          <p className="mt-4 max-w-3xl text-base text-tc-text-dim">
            This page is for people building modules for the ThreatCrush marketplace at{" "}
            <Link href="/store" className="text-tc-green hover:underline">threatcrush.com/store</Link>.
            It focuses on what contributors can do today, what metadata the platform expects, and what parts of the module ecosystem are still planned.
          </p>
        </div>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// CURRENT MODEL</p>
          <h2 className="mt-2 text-2xl font-bold text-white">How module contribution works today</h2>
          <div className="mt-4 space-y-4 text-sm text-tc-text-dim">
            <p>
              Today, the module contribution flow is primarily a <span className="text-white">marketplace publishing flow</span>.
              You provide a Git URL or website URL, ThreatCrush fetches metadata, you review it, and then publish the listing.
            </p>
            <p>
              The listing/store side is real now. The deeper runtime/module execution contract is still evolving, so this page separates <span className="text-tc-green">supported marketplace behavior</span> from <span className="text-yellow-400">planned runtime behavior</span>.
            </p>
          </div>
        </section>

        <section className="mb-12">
          <p className="font-mono text-sm text-tc-green tracking-wider">// SUPPORTED</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Supported contributor flow</h2>
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            {supportedContributorPaths.map((item) => (
              <div key={item.title} className="rounded-xl border border-tc-border bg-tc-card p-5">
                <h3 className="text-lg font-bold text-white">{item.title}</h3>
                <p className="mt-3 text-sm text-tc-text-dim">{item.description}</p>
                <Link href={item.href} className="mt-5 inline-block text-sm font-semibold text-tc-green hover:underline">
                  {item.cta} →
                </Link>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12">
          <p className="font-mono text-sm text-tc-green tracking-wider">// API REFERENCE</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Module Store HTTP API</h2>
          <p className="mt-3 max-w-3xl text-sm text-tc-text-dim">
            The full reference — request/response shapes, auth modes, error codes, and worked
            examples — lives in <a href={API_REFERENCE_URL} className="text-tc-green hover:underline" target="_blank" rel="noopener noreferrer">docs/MODULE_STORE_API.md</a>.
            Endpoints at a glance:
          </p>
          <div className="mt-6 overflow-x-auto rounded-xl border border-tc-border bg-tc-card">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-tc-border bg-tc-darker/40">
                <tr className="text-tc-text-dim">
                  <th className="px-4 py-3 font-mono text-xs uppercase tracking-wider">Method</th>
                  <th className="px-4 py-3 font-mono text-xs uppercase tracking-wider">Path</th>
                  <th className="px-4 py-3 font-mono text-xs uppercase tracking-wider">Auth</th>
                  <th className="px-4 py-3 font-mono text-xs uppercase tracking-wider">Purpose</th>
                </tr>
              </thead>
              <tbody>
                {apiEndpoints.map((ep) => (
                  <tr key={`${ep.method} ${ep.path}`} className="border-b border-tc-border/40 last:border-0">
                    <td className="px-4 py-3 font-mono text-xs">
                      <span className={
                        ep.method === "GET" ? "text-tc-green" :
                        ep.method === "POST" ? "text-yellow-400" :
                        ep.method === "PATCH" ? "text-blue-400" :
                        "text-red-400"
                      }>{ep.method}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-white">{ep.path}</td>
                    <td className="px-4 py-3 font-mono text-xs text-tc-text-dim">
                      {ep.auth === "none" ? "—" : ep.auth === "bearer" ? "Bearer" : "email"}
                    </td>
                    <td className="px-4 py-3 text-tc-text-dim">{ep.purpose}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            <a href={API_REFERENCE_URL} target="_blank" rel="noopener noreferrer" className="rounded-lg border border-tc-green/30 px-4 py-2 text-sm font-bold text-tc-green hover:bg-tc-green/10">
              Read the full API reference →
            </a>
          </div>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// BOILERPLATES</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Starter templates</h2>
          <p className="mt-3 max-w-3xl text-sm text-tc-text-dim">
            Three working starters in the repo. Clone the one closest to what you&apos;re shipping
            and rename it. Each ships with <code className="text-tc-green">mod.toml</code>,
            a <code className="text-tc-green">src/</code> layout, and a README.
          </p>
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            {boilerplates.map((b) => (
              <a key={b.name} href={b.href} target="_blank" rel="noopener noreferrer" className="rounded-xl border border-tc-border bg-tc-darker/40 p-5 transition-colors hover:border-tc-green/40">
                <p className="font-mono text-sm text-tc-green">{b.name}</p>
                <p className="mt-3 text-sm text-tc-text-dim">{b.description}</p>
                <p className="mt-4 text-xs font-semibold text-tc-green">View on GitHub →</p>
              </a>
            ))}
          </div>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// REQUIRED METADATA</p>
          <h2 className="mt-2 text-2xl font-bold text-white">What your module listing should include</h2>
          <div className="mt-6 grid gap-8 md:grid-cols-2">
            <div>
              <h3 className="text-lg font-bold text-white">Required</h3>
              <ul className="mt-4 list-disc space-y-2 pl-6 text-sm text-tc-text-dim">
                {requiredMetadata.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Recommended</h3>
              <ul className="mt-4 list-disc space-y-2 pl-6 text-sm text-tc-text-dim">
                {recommendedMetadata.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// QUALITY BAR</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Module listing quality guidelines</h2>
          <ul className="mt-5 list-disc space-y-3 pl-6 text-sm text-tc-text-dim">
            <li>Use a stable, clean slug/name that will still make sense a year from now.</li>
            <li>Write a concrete description: what it detects, scans, automates, or integrates with.</li>
            <li>Include real screenshots or branding assets when possible.</li>
            <li>Link to a real repo or homepage that explains the module and shows signs of maintenance.</li>
            <li>Use accurate pricing metadata. If it is paid, be explicit about what the buyer gets.</li>
            <li>Do not market vaporware as a finished installable runtime module if it is still just a concept.</li>
          </ul>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-yellow-400 tracking-wider">// PLANNED</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Planned module-author features</h2>
          <ul className="mt-5 list-disc space-y-3 pl-6 text-sm text-tc-text-dim">
            {plannedModuleFeatures.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// PUBLISH NOW</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Ready to list a module?</h2>
          <p className="mt-4 text-sm text-tc-text-dim">
            If you already have a repo or product URL, use the publish flow now. ThreatCrush will try to fetch metadata automatically, and you can review/edit it before submitting.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/store/publish" className="rounded-lg bg-tc-green px-5 py-3 font-semibold text-black hover:bg-tc-green-dim">
              Publish a module →
            </Link>
            <Link href="/store" className="rounded-lg border border-tc-border px-5 py-3 font-semibold text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green">
              Browse store
            </Link>
          </div>
        </section>
      </div>
    </main>
  );
}
