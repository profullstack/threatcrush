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
    status: "Publishing (unsigned)",
    description: "On every version tag, publishes a GitHub Release with macOS .dmg/.zip (Apple silicon and Intel), a Windows x64 NSIS installer, a Linux AppImage and .deb, and SHA256SUMS.txt. macOS/Windows signing and macOS notarization switch on automatically once their secrets are configured; until then those builds are unsigned.",
  },
  {
    name: "npm Publish",
    file: ".github/workflows/npm-publish.yml",
    status: "Publishing the CLI",
    description: "Publishes @profullstack/threatcrush to npm on every version tag; manual dispatch supports a dry run. A second job publishes the module SDK, @threatcrush/sdk, from the same tags; it is not on npm yet.",
  },
  {
    name: "Docker Publish",
    file: ".github/workflows/docker-publish.yml",
    status: "Publishing to GHCR (private)",
    description: "Builds and pushes ghcr.io/profullstack/threatcrush:{latest,version} on every version tag. The GHCR package is not public yet, so anonymous pulls are refused; Docker Hub is skipped until its credentials exist.",
  },
  {
    name: "Submit to Package Managers",
    file: ".github/workflows/submit-packages.yml",
    status: "Not running",
    description: "Submits artifacts/manifests to package managers when a GitHub Release is published or on manual dispatch. It has not run since August 2026: releases are published with the default GITHUB_TOKEN, which does not trigger other workflows, and the packaging secrets are not configured.",
  },
  {
    name: "Mobile Release",
    file: ".github/workflows/mobile-release.yml",
    status: "Android builds on tags",
    description: "Builds the Android app with Expo/EAS on every version tag (production profile). iOS builds and store submission are manual-dispatch options that have not been run successfully yet.",
  },
];

const requiredSecrets = [
  "EXPO_TOKEN for Expo/EAS mobile builds (configured)",
  "NPM_TOKEN for CLI publishing (configured)",
  "DOCKER_USERNAME and DOCKER_TOKEN for Docker Hub publishing (not configured; images go to GHCR only)",
  "APPLE_CERTIFICATE and APPLE_CERTIFICATE_PASSWORD to sign the macOS desktop app, plus APPLE_API_KEY, APPLE_API_KEY_ID and APPLE_API_ISSUER (or APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD and APPLE_TEAM_ID) to notarize it",
  "WINDOWS_CERTIFICATE and WINDOWS_CERTIFICATE_PASSWORD to sign the Windows desktop installer",
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
          <h2 className="text-2xl font-bold text-white">Release secrets</h2>
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
