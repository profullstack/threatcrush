import Link from "next/link";

const supportedCommands = [
  {
    name: "threatcrush update",
    description: "Update the installed bundle based on recorded install mode.",
    notes: "Real command. On Linux server installs this means CLI. On desktop-oriented installs it can include the desktop bundle too.",
  },
  {
    name: "threatcrush remove",
    description: "Remove the installed bundle.",
    notes: "Real command. Alias: `threatcrush uninstall`.",
  },
  {
    name: "threatcrush uninstall",
    description: "Alias for `threatcrush remove`.",
    notes: "Real alias.",
  },
  {
    name: "threatcrush store",
    description: "Browse the module marketplace.",
    notes: "Real command, but currently gated behind the waitlist flow.",
  },
  {
    name: "threatcrush store search <query>",
    description: "Search modules in the marketplace.",
    notes: "Real command, currently gated.",
  },
  {
    name: "threatcrush store publish <url>",
    description: "Publish a module from a git URL or website URL.",
    notes: "Real command. Fetches metadata, previews it, then publishes to the store.",
  },
  {
    name: "threatcrush modules [action] [name]",
    description: "Entry point for module management.",
    notes: "Real command entry exists, but module lifecycle behavior is still gated / early.",
  },
  {
    name: "threatcrush monitor",
    description: "Real-time monitoring command surface.",
    notes: "Command exists today, but product behavior is still beta-gated while the daemon/runtime catches up.",
  },
  {
    name: "threatcrush tui",
    description: "Interactive dashboard command surface.",
    notes: "Command exists today, but the real TUI is still planned.",
  },
  {
    name: "threatcrush init",
    description: "Bootstrap/configure ThreatCrush on a host.",
    notes: "Command exists today, but full auto-detection is still planned.",
  },
  {
    name: "threatcrush scan",
    description: "Code and target scanning entry point.",
    notes: "Command exists today, but fully realized scanning behavior is still planned.",
  },
  {
    name: "threatcrush pentest",
    description: "Penetration testing entry point.",
    notes: "Command exists today, but production-grade engine behavior is still planned.",
  },
  {
    name: "threatcrush status",
    description: "Status entry point for daemon/modules.",
    notes: "Command exists today, with fuller runtime status planned as the daemon solidifies.",
  },
  {
    name: "threatcrush start",
    description: "Start the daemon.",
    notes: "Command surface exists, but the real daemon/service lifecycle is still being built.",
  },
  {
    name: "threatcrush stop",
    description: "Stop the daemon.",
    notes: "Command surface exists, but the real daemon/service lifecycle is still being built.",
  },
  {
    name: "threatcrush logs",
    description: "Inspect runtime logs.",
    notes: "Command surface exists, but final logging/runtime behavior is still planned.",
  },
  {
    name: "threatcrush activate",
    description: "Activate a license key.",
    notes: "Real command surface, currently part of the beta-gated product flow.",
  },
];

const plannedItems = [
  "Fully functional `threatcrush tui` dashboard (htop-style security interface)",
  "Real `threatcrush init` host auto-detection and config generation",
  "Daemon/service lifecycle behind `start`, `stop`, `status`, and `logs`",
  "Fully realized `scan` and `pentest` engines",
  "Production-ready module install/remove/update lifecycle under `threatcrush modules`",
  "Richer desktop client documentation and dedicated desktop install docs",
  "Expanded operator docs for Linux server deployment and hardening",
];

export default function DocsPage() {
  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <div className="mx-auto max-w-5xl px-6 py-16">
        <div className="mb-12">
          <Link href="/" className="text-sm text-tc-green hover:underline">← Back to ThreatCrush</Link>
          <p className="mt-6 font-mono text-sm text-tc-green tracking-wider">// DOCS</p>
          <h1 className="mt-3 text-4xl font-black text-white">ThreatCrush Docs</h1>
          <p className="mt-4 max-w-3xl text-base text-tc-text-dim">
            Start here for the current command surface, install model, and what is already real versus what is still planned.
            This page is intentionally honest: supported behavior is listed separately from roadmap material.
          </p>
          <p className="mt-4 max-w-3xl text-base text-tc-text-dim">
            Right now, the <span className="text-tc-green">Module Store</span> is the clearest first destination after the basic install/docs/housekeeping work.
          </p>
        </div>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <h2 className="text-2xl font-bold text-white">Install model</h2>
          <div className="mt-4 space-y-3 text-sm text-tc-text-dim">
            <p>
              <span className="text-tc-green font-semibold">Preferred install:</span>{" "}
              <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">curl -fsSL https://threatcrush.com/install.sh | sh</code>
            </p>
            <ul className="list-disc space-y-2 pl-6">
              <li><span className="text-white">Linux server</span> → real host story, installs the CLI.</li>
              <li><span className="text-white">Linux desktop</span> → installs the CLI + desktop app.</li>
              <li><span className="text-white">Windows desktop</span> → desktop client only, connects to a ThreatCrush server elsewhere.</li>
              <li><span className="text-white">macOS desktop</span> → desktop-oriented client story.</li>
            </ul>
            <p>
              After install, lifecycle commands are <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">threatcrush update</code> and{" "}
              <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">threatcrush remove</code>.
            </p>
          </div>
        </section>

        <section className="mb-12">
          <div className="mb-6 flex items-end justify-between gap-4">
            <div>
              <p className="font-mono text-sm text-tc-green tracking-wider">// SUPPORTED</p>
              <h2 className="mt-2 text-2xl font-bold text-white">Commands we support today</h2>
            </div>
          </div>

          <div className="space-y-4">
            {supportedCommands.map((command) => (
              <div key={command.name} className="rounded-xl border border-tc-border bg-tc-card p-5">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div className="flex-1">
                    <code className="font-mono text-sm text-tc-green">{command.name}</code>
                    <p className="mt-2 text-sm text-white">{command.description}</p>
                    <p className="mt-2 text-sm text-tc-text-dim">{command.notes}</p>
                  </div>
                  <span className="rounded-full border border-tc-green/30 bg-tc-green/10 px-3 py-1 text-xs font-semibold text-tc-green">
                    Supported surface
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-yellow-400 tracking-wider">// PLANNED</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Planned / not fully implemented yet</h2>
          <ul className="mt-5 list-disc space-y-3 pl-6 text-sm text-tc-text-dim">
            {plannedItems.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// START WITH THE STORE</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Why the marketplace matters first</h2>
          <div className="mt-4 space-y-3 text-sm text-tc-text-dim">
            <p>
              ThreatCrush is still building out the broader daemon/runtime/operator experience. The module marketplace is the first area where contributors and early users can do something concrete today.
            </p>
            <ul className="list-disc space-y-2 pl-6">
              <li>Browse the ecosystem at <span className="text-tc-green">/store</span></li>
              <li>Publish new listings at <span className="text-tc-green">/store/publish</span></li>
              <li>Read contributor guidance at <span className="text-tc-green">/docs/modules</span></li>
            </ul>
          </div>
        </section>

        <section className="rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// MODULE AUTHORS</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Building and publishing modules</h2>
          <p className="mt-4 text-sm text-tc-text-dim">
            If you want to contribute to the marketplace, start with the module author docs.
            They explain how the store works today, what metadata we fetch, and how to publish through the web UI or CLI.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/docs/modules" className="rounded-lg bg-tc-green px-5 py-3 font-semibold text-black hover:bg-tc-green-dim">
              Read module docs →
            </Link>
            <Link href="/docs/releases" className="rounded-lg border border-tc-border px-5 py-3 font-semibold text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green">
              Release automation docs
            </Link>
            <Link href="/store" className="rounded-lg border border-tc-border px-5 py-3 font-semibold text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green">
              Browse module store
            </Link>
            <Link href="/store/publish" className="rounded-lg border border-tc-border px-5 py-3 font-semibold text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green">
              Publish a module
            </Link>
          </div>
        </section>
      </div>
    </main>
  );
}
