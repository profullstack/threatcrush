import Link from "next/link";

const workflows = [
  {
    name: "PR Checks",
    file: ".github/workflows/pr-checks.yml",
    status: "Active baseline",
    description: "Runs on pushes and pull requests to main/master. This is the workflow that is definitely active right now.",
  },
  {
    name: "Desktop Release",
    file: ".github/workflows/desktop-release.yml",
    status: "Release workflow present",
    description: "Builds desktop artifacts for macOS, Windows, and Linux on version tags or manual dispatch. Needs signing/release secrets to be truly production-ready.",
  },
  {
    name: "CLI npm Publish",
    file: ".github/workflows/npm-publish.yml",
    status: "Release workflow present",
    description: "Publishes the CLI package on version tags or manual dispatch, assuming the npm token is configured.",
  },
  {
    name: "Docker Publish",
    file: ".github/workflows/docker-publish.yml",
    status: "Release workflow present",
    description: "Builds and pushes Docker images on version tags or manual dispatch, assuming registry credentials are configured.",
  },
  {
    name: "Submit to Package Managers",
    file: ".github/workflows/submit-packages.yml",
    status: "Release workflow present",
    description: "Submits artifacts/manifests to package managers after release publication or manual dispatch. Requires multiple packaging secrets.",
  },
  {
    name: "Mobile Release",
    file: ".github/workflows/mobile-release.yml",
    status: "New Expo/EAS workflow",
    description: "Builds native mobile artifacts with Expo/EAS for preview or production and can optionally auto-submit production builds.",
  },
];

const requiredSecrets = [
  "EXPO_TOKEN for Expo/EAS mobile builds",
  "NPM_TOKEN for CLI publishing",
  "DOCKER_USERNAME and DOCKER_TOKEN for Docker Hub publishing",
  "Apple signing/notarization secrets for desktop macOS releases",
  "Windows certificate secrets for signed Windows desktop releases",
  "Package-manager submission secrets (AUR/GPG/Chocolatey/etc.) when using submit-packages",
];

export default function ReleasesDocsPage() {
  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <div className="mx-auto max-w-5xl px-6 py-16">
        <div className="mb-12">
          <Link href="/docs" className="text-sm text-tc-green hover:underline">← Back to Docs</Link>
          <p className="mt-6 font-mono text-sm text-tc-green tracking-wider">// DOCS / RELEASES</p>
          <h1 className="mt-3 text-4xl font-black text-white">Release Automation</h1>
          <p className="mt-4 max-w-3xl text-base text-tc-text-dim">
            ThreatCrush now has workflow definitions for CLI publishing, desktop releases, Docker publishing, package-manager submissions, and native Expo/EAS mobile builds.
            The important distinction is whether a workflow file merely exists versus whether the required secrets and release habits are actually in place.
          </p>
        </div>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <h2 className="text-2xl font-bold text-white">Current workflow map</h2>
          <div className="mt-6 space-y-4">
            {workflows.map((workflow) => (
              <div key={workflow.name} className="rounded-xl border border-tc-border bg-black/20 p-5">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <h3 className="text-lg font-bold text-white">{workflow.name}</h3>
                    <p className="mt-1 font-mono text-xs text-tc-green">{workflow.file}</p>
                    <p className="mt-3 text-sm text-tc-text-dim">{workflow.description}</p>
                  </div>
                  <span className="rounded-full border border-tc-green/30 bg-tc-green/10 px-3 py-1 text-xs font-semibold text-tc-green">
                    {workflow.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <h2 className="text-2xl font-bold text-white">Secrets / infra still needed</h2>
          <ul className="mt-5 list-disc space-y-3 pl-6 text-sm text-tc-text-dim">
            {requiredSecrets.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <h2 className="text-2xl font-bold text-white">Repo TODO docs</h2>
          <div className="mt-4 space-y-3 text-sm text-tc-text-dim">
            <p>
              Release/setup gaps are also documented directly in the repo under <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">docs/</code> so they do not live only in chat context.
            </p>
            <ul className="list-disc space-y-2 pl-6">
              <li><code className="font-mono text-tc-green">docs/MOBILE_RELEASE_TODO.md</code></li>
              <li><code className="font-mono text-tc-green">docs/DESKTOP_RELEASE_TODO.md</code></li>
              <li><code className="font-mono text-tc-green">docs/RELEASE_STATUS.md</code></li>
            </ul>
          </div>
        </section>

        <section className="rounded-2xl border border-tc-border bg-tc-card p-8">
          <h2 className="text-2xl font-bold text-white">Recommended release path</h2>
          <div className="mt-4 space-y-3 text-sm text-tc-text-dim">
            <p><span className="text-white font-semibold">1.</span> Keep PR Checks green on normal branch work.</p>
            <p><span className="text-white font-semibold">2.</span> Cut version tags when you actually want release automation to fire.</p>
            <p><span className="text-white font-semibold">3.</span> Use workflow dispatch for dry runs and partial release testing.</p>
            <p><span className="text-white font-semibold">4.</span> Treat the site copy as production-ready only after the related workflow is proven in the Actions UI.</p>
          </div>
        </section>
      </div>
    </main>
  );
}
